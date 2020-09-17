#pragma once
#define		LOCKD	int

void locker_client_init(const char *ip, int port, int max_interval);
LOCKD locker_client_lock(const char *resource);

void locker_client_unlock(LOCKD lockd);
