#ifndef _H_FILE_OPERATION_
#define _H_FILE_OPERATION_
#include <fcntl.h>

enum {
	FILE_COMPARE_FAIL = -1,
	FILE_COMPARE_SAME,
	FILE_COMPARE_DIFFERENT
};

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

void file_operation_init(const char *gateway_path);
extern int file_operation_run(void);
int file_operation_compare(const char *file1, const char *file2);

void file_operation_broadcast(const char *src_file, const char *dst_file);
extern int file_operation_stop(void);
extern void file_operation_free(void);

#endif
