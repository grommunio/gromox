// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/endian.hpp>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#define MAX_LINE			1024

using namespace gromox;

static BOOL list_file_analyse_format(LIST_FILE* list_file, const char* format);
static BOOL list_file_parse_line(LIST_FILE* list_file, char* pfile, char* line);
static BOOL list_file_construct_list(LIST_FILE* list_file);

static std::unique_ptr<LIST_FILE> list_file_alloc(const char *format)
{
	std::unique_ptr<LIST_FILE> lf;
	try {
		lf = std::make_unique<LIST_FILE>();
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
	if (!list_file_analyse_format(lf.get(), format)) {
		errno = EINVAL;
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
static std::unique_ptr<LIST_FILE> list_file_init(const char *filename, const char *format)
{
	auto list_file = list_file_alloc(format);
	if (list_file == NULL)
		return NULL;
	list_file->file_ptr.reset(fopen(filename, "r"));
	if (list_file->file_ptr == nullptr) {
		return NULL;
	}
	if (!list_file_construct_list(list_file.get()))
		return NULL;
	return list_file;
}

std::unique_ptr<LIST_FILE> list_file_initd(const char *fb, const char *sdlist,
    const char *format, unsigned int mode)
{
	if (sdlist == nullptr || strchr(fb, '/') != nullptr) {
		auto cfg = list_file_init(fb, format);
		if (cfg != nullptr)
			return cfg;
		if (errno == ENOENT && mode == EMPTY_ON_ABSENCE)
			return list_file_alloc(format);
		return nullptr;
	}
	errno = 0;
	try {
		for (auto dir : gx_split(sdlist, ':')) {
			if (dir.size() == 0)
				continue;
			errno = 0;
			auto full = dir + "/" + fb;
			auto cfg = list_file_init(full.c_str(), format);
			if (cfg != nullptr)
				return cfg;
			if (errno != ENOENT) {
				fprintf(stderr, "list_file_initd %s: %s\n",
				        full.c_str(), strerror(errno));
				return nullptr;
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
	return mode == EMPTY_ON_ABSENCE ? list_file_alloc(format) : nullptr;
}

LIST_FILE::~LIST_FILE()
{
	if (pfile != nullptr)
		free(pfile);
}

static BOOL list_file_analyse_format(LIST_FILE *list_file, const char* format)
{
	int i, num = 0, distance;
	char temp_buf[64];
	
#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_analyse_format, param NULL");
		return FALSE;
	}
#endif
	auto ptr = format;
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
				auto temp_ptr = strchr(ptr, '%');
				if (NULL == temp_ptr) {
					gx_strlcpy(temp_buf, ptr, GX_ARRAY_SIZE(temp_buf));
					/* make the while loop exit */
					ptr = (char*)format + strlen(format) - 1;
				} else {
					distance = temp_ptr - ptr;
					memcpy(temp_buf, ptr, distance);
					temp_buf[distance] = '\0';
					ptr = temp_ptr - 1;
				}
				if (strlen(temp_buf) == 0) {
					printf("[list_file]: invalid format, should have a "
							"number after \":\"\n");
					return FALSE;
				}
				list_file->type_size[num] = strtol(temp_buf, nullptr, 0);
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
 *	read lines of file into object
 *	@param
 *		list_file [in]			object pointer
 *	@return
 *		TRUE					OK
 *		FALSE					fail
 */
static BOOL list_file_construct_list(LIST_FILE* list_file)
{
	char line[MAX_LINE];
	int table_size;

#ifdef _DEBUG_UMTA
	if (NULL == list_file) {
		debug_info("[list_file]: list_file_construct_list, param NULL");
		return FALSE;
	}
#endif
	/* calculate the line number in file */
	for (table_size = 0; fgets(line, MAX_LINE, list_file->file_ptr.get()); ++table_size) {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			table_size --;
		}
	}
	list_file->item_num = 0;
	rewind(list_file->file_ptr.get());
	auto ptr = gromox::me_alloc<char>(table_size * list_file->item_size);
	if (NULL == ptr) {
		printf("[list_file]: allocate memory fail\n");
		return FALSE;
	}
	list_file->pfile = ptr;
	while (fgets(line, MAX_LINE, list_file->file_ptr.get())) {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			/* skip empty line or comments */
			continue;
		}
		/* prevent line exceed maximum length ---MAX_LEN */
		line[sizeof(line) - 1] = '\0';
		if (list_file_parse_line(list_file, ptr, line)) {
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
			if (sizeof(long) == sizeof(int64_t))
				cpu_to_le64p(pfile, strtoll(temp_buf, nullptr, 0));
			else
				cpu_to_le32p(pfile, strtoll(temp_buf, nullptr, 0));
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
			if (sizeof(int) == sizeof(int32_t))
				cpu_to_le32p(pfile, strtol(temp_buf, nullptr, 0));
			else
				cpu_to_le16p(pfile, strtol(temp_buf, nullptr, 0));
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
		if (b_terminate && i != list_file->type_num - 1)
			return FALSE;
	}
	return b_terminate;
}

errno_t list_file_read_fixedstrings(const char *filename, const char *sdlist,
    std::vector<std::string> &out)
{
	struct item { char data[256]; };
	auto plist = list_file_initd(filename, sdlist, "%s:256", ERROR_ON_ABSENCE);
	if (plist == nullptr)
		return errno;
	auto num = plist->get_size();
	auto pitem = static_cast<const item *>(plist->get_list());
	for (decltype(num) i = 0; i < num; ++i) {
		try {
			out.emplace_back(pitem[i].data);
		} catch (const std::bad_alloc &) {
			return ENOMEM;
		}
	}
	return 0;
}

errno_t list_file_read_exmdb(const char *filename, const char *sdlist,
    std::vector<EXMDB_ITEM> &out)
{
	struct raw {
		char prefix[256], type[16], host[40];
		int port;
	};
	auto plist = list_file_initd(filename, sdlist, "%s:256%s:16%s:40%d", ERROR_ON_ABSENCE);
	if (plist == nullptr && errno == ENOENT) {
		EXMDB_ITEM e;
		e.prefix = PKGSTATEDIR "/user/";
		e.host   = "::1";
		e.port   = 5000;
		e.type   = EXMDB_ITEM::EXMDB_PRIVATE;
		out.push_back(e);
		e.prefix = PKGSTATEDIR "/domain/";
		e.type   = EXMDB_ITEM::EXMDB_PUBLIC;
		out.push_back(std::move(e));
		return 0;
	} else if (plist == nullptr) {
		return errno;
	}
	auto num = plist->get_size();
	auto item = static_cast<const raw *>(plist->get_list());
	for (decltype(num) i = 0; i < num; ++i) {
		EXMDB_ITEM e;
		if (strcmp(item[i].type, "public") == 0) {
			e.type = EXMDB_ITEM::EXMDB_PUBLIC;
		} else if (strcmp(item[i].type, "private") == 0) {
			e.type = EXMDB_ITEM::EXMDB_PRIVATE;
		} else {
			fprintf(stderr, "list_file_read_exmdb:%s: skipping line with illegal type \"%s\"\n",
			        filename, item[i].type);
			continue;
		}
		e.prefix = item[i].prefix;
		e.host   = item[i].host;
		e.port   = item[i].port;
		out.push_back(std::move(e));
	}
	return 0;
}
