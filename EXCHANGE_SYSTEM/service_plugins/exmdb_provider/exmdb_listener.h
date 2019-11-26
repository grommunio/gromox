#ifndef _H_EXMDB_LISTENER_
#define _H_EXMDB_LISTENER_

void exmdb_listener_init(const char *ip,
	int port, const char *list_path);
extern int exmdb_listener_run(void);
extern int exmdb_listener_trigger_accept(void);
extern int exmdb_listener_stop(void);
extern void exmdb_listener_free(void);

#endif /* _H_EXMDB_LISTENER_ */
