#ifndef _H_FILE_OPERATION_
#define _H_FILE_OPERATION_

void file_operation_init();

int file_operation_run();

void file_operation_compress(const char *src_path, const char *dst_file);

void file_operation_copy_file(const char *src_file, const char *dst_file);

void file_operation_copy_dir(const char *src_dir, const char *dst_dir);

void file_operation_remove_dir(const char *path);

int file_operation_stop();

void file_operation_free();

#endif
