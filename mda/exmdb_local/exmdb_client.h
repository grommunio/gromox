#pragma once
#include <gromox/element_data.hpp>

#define EXMDB_RESULT_OK			0
#define EXMDB_RUNTIME_ERROR		1
#define EXMDB_NO_SERVER			2
#define EXMDB_RDWR_ERROR		3
#define EXMDB_RESULT_ERROR		4
#define EXMDB_MAILBOX_FULL		5

extern void exmdb_client_init(int conn_num);
extern int exmdb_client_run();
extern int exmdb_client_stop();
int exmdb_client_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest);

int exmdb_client_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found);
	
BOOL exmdb_client_get_exmdb_information(
	const char *dir, char *ip_addr, int *pport,
	int *pconn_num, int *palive_conn);
