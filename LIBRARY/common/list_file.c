// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <errno.h>
#include <stdbool.h>
#include "list_file.h"
#include "common_types.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#define MAX_LINE			1024

static BOOL list_file_analyse_format(LIST_FILE* list_file, const char* format);
static BOOL list_file_parse_line(LIST_FILE* list_file, char* pfile, char* line);
static BOOL list_file_construct_list(LIST_FILE* list_file);

static LIST_FILE *list_file_alloc(const char *format)
{
	LIST_FILE *lf = calloc(1, sizeof(*lf));
	if (lf == NULL)
		return NULL;
	if (!list_file_analyse_format(lf, format)) {
		free(lf);
		return NULL;
	}
	return lf;
}

/*
 *	initialize the list file
 *	@param
 *		filename [in]			list file name
 *		format					format of list item
 *								"%l" presents long integer,
 *								"%d" presents integer,
 *								"%s" presents string, length locates after ':'
 *								e.g. "%s:10%d%d" means ten bytes string and
 *								two integers
 *		item_len				length of list item in bytes
 *	@return
 *		NULL					fail
 *		<>NULL					object pointer
 *
 */
LIST_FILE *list_file_init3(const char *filename, const char *format, bool hard)
{
	LIST_FILE *list_file = list_file_alloc(format);
	if (list_file == NULL)
		return NULL;
	FILE *file_ptr = fopen(filename, "r");
	if (file_ptr == NULL) {
		if (errno == ENOENT && !hard)
			return list_file;
		debug_info("[list_file]: cannot open %s: %s", filename, strerror(errno));
		free(list_file);
		return NULL;
	}
	list_file->file_ptr = file_ptr;
	if (FALSE == list_file_construct_list(list_file)) {
		free(list_file);
		fclose(file_ptr);
		return NULL;
	}
	return list_file;
}

LIST_FILE *list_file_init(const char *filename, const char *format)
{
	return list_file_init3(filename, format, true);
}

/*
 *	free list file object
 *	@param
 *		file [in]	object pointer
 */
void list_file_free(LIST_FILE* list_file)
{
#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_free, param NULL");
		return;
	}
#endif
	if (list_file->file_ptr != NULL)
		fclose(list_file->file_ptr);
	if (NULL != list_file->pfile) {
		free(list_file->pfile);
	}
	free(list_file);
}

static BOOL list_file_analyse_format(LIST_FILE *list_file, const char* format)
{
	char *ptr, *temp_ptr;
	int i, num = 0, distance;
	char temp_buf[64];
	
#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_analyse_format, param NULL");
		return FALSE;
	}
#endif
	ptr = (char*) format;
	while ('\0' != *ptr) {
		if ('%' == *ptr) {
			ptr++;
			switch(*ptr) {
			case 'l':
				list_file->format[num]	  = 'l';
				list_file->type_size[num] = sizeof(long);
				num ++;
				ptr ++;
				break;
			case 'd':
				list_file->format[num]	  = 'd';
				list_file->type_size[num] = sizeof(int);
				num ++;
				ptr ++;
				break;
			case 's':
				list_file->format[num] = 's';
				ptr ++;
				if (':' != *ptr) {
					printf("[list_file]: invalid format, should have a "
							"\":\" after \"s\"\n");
					return FALSE;
				}
				ptr ++;
				temp_ptr = strchr(ptr, '%');
				if (NULL == temp_ptr) {
					strcpy(temp_buf, ptr);
					/* make the while loop exit */
					ptr = (char*)format + strlen(format) - 1;
				} else {
					distance = temp_ptr - ptr;
					memcpy(temp_buf, ptr, distance);
					temp_buf[distance] = '\0';
					ptr = temp_ptr - 1;
				}
				if (strlen(temp_buf) == 0) {
					printf("[list_file]: invalid fromat, should have a "
							"number after \":\"\n");
					return FALSE;
				}
				list_file->type_size[num] = atoi(temp_buf);
				if (list_file->type_size[num] <= 0) {
					printf("[list_file]: invalid format, length follows "
							"should be larger than 0\n");
					return FALSE;
				}
				num ++;
				break;
			}
		} else {
			ptr ++;
		}
	}
	if (0 == num || num > 32) {
		return FALSE;
	}
	list_file->type_num = num;
	list_file->item_size = 0;
	for (i=0; i<num; i++) {
		list_file->item_size += list_file->type_size[i];
	}
	return TRUE;
}

/*
 *	get list file's list
 *	@param
 *		list_file [in]		object pointer
 *	@return
 *		pointer to list file
 */
void* list_file_get_list(LIST_FILE* list_file)
{
#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_get_list, param NULL");
		return NULL;
	}
#endif
	return list_file->pfile;
}

/*
 *	read lines of file into object
 *	@param
 *		list_file [in]			object pointer
 *	@return
 *		TRUE					OK
 *		FALSE					fail
 */
static BOOL list_file_construct_list(LIST_FILE* list_file)
{
	char line[MAX_LINE], *ptr;
	int table_size;

#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_construct_list, param NULL");
		return FALSE;
	}
#endif
	/* calculate the line number in file */
	for (table_size=0;fgets(line, MAX_LINE, list_file->file_ptr);table_size++) {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			table_size --;
		}
	}
	list_file->item_num = 0;

	rewind(list_file->file_ptr);
	ptr = malloc(table_size * list_file->item_size);
	if (NULL == ptr) {
		printf("[list_file]: allocate memory fail\n");
		return FALSE;
	}
	list_file->pfile = ptr;
	while (fgets(line, MAX_LINE, list_file->file_ptr)) {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			/* skip empty line or comments */
			continue;
		}
		/* prevent line exceed maximum length ---MAX_LEN */
		line[sizeof(line) - 1] = '\0';
		if (TRUE == list_file_parse_line(list_file, ptr, line)) {
			list_file->item_num ++;
			ptr += list_file->item_size;
		}
	}
	return TRUE;
}

static BOOL list_file_parse_line(LIST_FILE* list_file, char* pfile, char* line)
{
	char *ptr = line;
	char temp_buf[MAX_LINE];
	int i, j;
	BOOL b_terminate = FALSE;

#ifdef _DEBUG_UMTA
	if (NULL == list_file || NULL == pfile || NULL == line) {
		debug_info("[list_file]: list_file_parse_line, param NULL");
		return FALSE;
	}
#endif
	
	for (i=0; i<list_file->type_num; i++) {
		switch (list_file->format[i]) {
		case 'l':
			/* trim ' ' or '\t' */
			while ('\0' != *ptr && '#' != *ptr && '\r' != *ptr &&
				   '\n' != *ptr && (' ' == *ptr || '\t' == *ptr)) {
				ptr ++;
			}
			if ('\0' == *ptr || '#' == *ptr || '\r' == *ptr || '\n' == *ptr) {
				return FALSE;
			}
			j = 0;
			while ('\t' != *ptr && ' ' != *ptr && '\r' != *ptr &&
				   '\0' != *ptr && '#' != *ptr && '\n' != *ptr) {
				temp_buf[j] = *ptr;
				j ++;
				ptr ++;
			}
			temp_buf[j] = '\0';
			*((long*)pfile) = atol(temp_buf);
			pfile += sizeof(long);
			if ('\0' == *ptr || '#' == *ptr || '\r' == *ptr || '\n' == *ptr) {
				b_terminate = TRUE;
			}
			break;
		case 'd':
			/* trim ' ' or '\t' */
			while ('\0' != *ptr && '#' != *ptr && '\r' != *ptr &&
				   '\n' != *ptr && (' ' == *ptr || '\t' == *ptr)) {
				ptr ++;
			}
			if ('\0' == *ptr || '#' == *ptr || '\r' == *ptr || '\n' == *ptr) {
				return FALSE;
			}
			j = 0;
			while ('\t' != *ptr && ' ' != *ptr && '\r' != *ptr &&
				   '\0' != *ptr && '#' != *ptr && '\n' != *ptr) {
				temp_buf[j] = *ptr;
				j ++;
				ptr ++;
			}
			temp_buf[j] = '\0';
			*((int*)pfile) = atoi(temp_buf);
			pfile += sizeof(int);
			if ('\0' == *ptr || '#' == *ptr || '\r' == *ptr || '\n' == *ptr) {
				b_terminate = TRUE;
			}
			break;
		case 's':
			/* trim ' ' or '\t' */
			while ('\0' != *ptr && '#' != *ptr && '\r' != *ptr &&
				  '\n' != *ptr && (' ' == *ptr || '\t' == *ptr)) {
				ptr ++;
			}
			if ('\0' == *ptr || '#' == *ptr || '\r' == *ptr || '\n' == *ptr) {
				return FALSE;
			}
			j = 0;
			while ('\t' != *ptr && ' ' != *ptr && '\r' != *ptr &&
				   '\0' != *ptr && '#' != *ptr && '\n' != *ptr) {
				if ('\\' == *ptr) {
					ptr ++;
					if (!('#' == *ptr || ' ' == *ptr || '\t' == *ptr ||
						'\\' == *ptr) || '\0' == *ptr)	{
						return FALSE;
					}
				}
				temp_buf[j] = *ptr;
				j ++;
				ptr ++;
			}
			if (j > list_file->type_size[i] - 1) {
				j = list_file->type_size[i] - 1;
			}
			temp_buf[j] = '\0';
			strcpy(pfile, temp_buf);
			pfile += list_file->type_size[i];
			if ('\0' == *ptr || '#' == *ptr || '\r' == *ptr || '\n' == *ptr) {
				b_terminate = TRUE;
			}
			break;
		}
		if (TRUE == b_terminate && i != list_file->type_num - 1) {
			return FALSE;
		}
	}
	return b_terminate;
}

int list_file_get_item_num(LIST_FILE* list_file)
{
#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_get_item_num, param NULL");
		return 0;
	}
#endif
	return list_file->item_num;
}

