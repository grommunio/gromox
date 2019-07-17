#ifndef _H_LIST_FILE_
#define _H_LIST_FILE_
#include <stdio.h>

typedef struct _LIST_FILE {
    FILE*       file_ptr;
    char        format[32];
    int         type_size[32];
    int         type_num;
    int         item_size;
    int         item_num;
    void*       pfile;
} LIST_FILE;

LIST_FILE* list_file_init(char* filename, const char* format);

void list_file_free(LIST_FILE* list_file);

void* list_file_get_list(LIST_FILE* list_file);

int list_file_get_item_num(LIST_FILE* list_file);

#endif /* _H_LIST_FILE_ */

