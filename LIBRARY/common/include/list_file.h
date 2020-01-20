#pragma once
#ifdef __cplusplus
#	include <cstdio>
#else
#	include <stdbool.h>
#	include <stdio.h>
#endif

typedef struct _LIST_FILE {
    FILE*       file_ptr;
    char        format[32];
    int         type_size[32];
    int         type_num;
    int         item_size;
    int         item_num;
    void*       pfile;
} LIST_FILE;

extern LIST_FILE *list_file_init3(const char *filename, const char *format, bool require);
extern LIST_FILE *list_file_init(const char *filename, const char *format);
void list_file_free(LIST_FILE* list_file);

void* list_file_get_list(LIST_FILE* list_file);

int list_file_get_item_num(LIST_FILE* list_file);
