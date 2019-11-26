#ifndef _H_EXMDB_LISTENER_
#define _H_EXMDB_LISTENER_

void exmdb_listener_init(const char *ip,
	int port, const char *list_path);

int exmdb_listener_run();

int exmdb_listener_trigger_accept();

int exmdb_listener_stop();

void exmdb_listener_free();


#endif /* _H_EXMDB_LISTENER_ */
