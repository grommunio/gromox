#ifndef _H_FILE_OPERATION_
#define _H_FILE_OPERATION_

extern void file_operation_init(void);
extern int file_operation_run(void);
void file_operation_compress(const char *src_path, const char *dst_file);

void file_operation_copy_file(const char *src_file, const char *dst_file);

void file_operation_copy_dir(const char *src_dir, const char *dst_dir);

void file_operation_remove_dir(const char *path);
extern int file_operation_stop(void);
extern void file_operation_free(void);

#endif
