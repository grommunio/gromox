#pragma once
#include <cstdint>
#include <ctime>
#include <gromox/ext_buffer.hpp>
#define APPLESINGLE_MAGIC	0x00051600
#define APPLEDOUBLE_MAGIC	0x00051607
#define APPLEFILE_VERSION	0x00020000

/* 
* Apple reserves the range of entry IDs from 1 to 0x7FFFFFFF.
* Entry ID 0 is invalid.  The rest of the range is available
* for applications to define their own entry types.  "Apple does
* not arbitrate the use of the rest of the range."
*/
#define AS_DATA			1	/* data fork */
#define AS_RESOURCE		2	/* resource fork */
#define AS_REALNAME		3	/* File's name on home file system */
#define AS_COMMENT		4	/* standard Mac comment */
#define AS_ICONBW		5	/* Mac black & white icon */
#define AS_ICONCOLOR	6	/* Mac color icon */
#define AS_FILEDATES	8	/* file dates; create, modify, etc */
#define AS_FINDERINFO	9	/* Mac Finder info & extended info */
#define AS_MACINFO		10	/* Mac file info, attributes, etc */
#define AS_PRODOSINFO	11	/* Pro-DOS file info, attrib., etc */
#define AS_MSDOSINFO	12	/* MS-DOS file info, attributes, etc */
#define AS_AFPNAME		13	/* Short name on AFP server */
#define AS_AFPINFO		14	/* AFP file info, attrib., etc */
#define AS_AFPDIRID		15	/* AFP directory ID */

struct FINDER_POINT {
   int16_t v; /* vertical coordinate */
   int16_t h; /* horizontal coordinate */
};

#define FD_FLAGS_FONDESK		0x0001	/* file is on desktop (HFS only) */
#define FD_FLAGS_MASKCOLOR		0x000E	/* color coding (3 bits) */
#define FD_FLAGS_FSWITCHLAUNCH	0x0020	/* reserved (System 7) */
#define FD_FLAGS_FSHARED		0x0040	/* appl available to multiple users */
#define FD_FLAGS_FNOINITS		0x0080	/* file contains no INIT resources */
#define FD_FLAGS_FBEENINITED	0x0100	/* Finder has loaded bundle res. */
#define FD_FLAGS_FCUSTOMICOM	0x0400	/* file contains custom icon */
#define FD_FLAGS_FSTATIONARY	0x0800	/* file is a stationary pad */
#define FD_FLAGS_FNAMELOCKED	0x1000	/* file can't be renamed by Finder */
#define FD_FLAGS_FHASBUNDLE		0x2000	/* file has a bundle */
#define FD_FLAGS_FINVISIBLE		0x4000	/* file's icon is invisible */
#define FD_FLAGS_FALIAS			0x8000	/* file is an alias file (System 7) */

/* Finder information */
struct FINFO {
	uint32_t fd_type;			/* File type, 4 ASCII chars */
	uint32_t fd_creator;		/* File's creator, 4 ASCII chars */
	uint16_t fd_flags;			/* Finder flag bits */
	FINDER_POINT fd_location;	/* file's location in folder */
	int16_t fd_folder;			/* file 's folder (aka window) */
};

/* Extended finder information */
struct FXINFO {
	int16_t fd_iconid;		/* icon ID number */
	int16_t fd_unused[3];	/* spare */
	int8_t fd_script; /* script flag and code */
	int8_t fd_xflags; /* reserved */
	int16_t fd_comment;		/* comment ID number */
	int32_t fd_putaway;		/* home directory ID */
};

/* header portion of AppleSingle */
struct ASHEADER {
	uint32_t magic_num;		/* internal file type tag */
	uint32_t version_num;	/* format version: 2 = 0x00020000 */
	uint8_t filler[16];		/* filler, currently all bits 0 */
};

/*
* matrix of entry types and their usage:
*
*                   Macintosh    Pro-DOS    MS-DOS    AFP server
*                   ---------    -------    ------    ----------
*  1   AS_DATA         xxx         xxx       xxx         xxx
*  2   AS_RESOURCE     xxx         xxx
*  3   AS_REALNAME     xxx         xxx       xxx         xxx
*  4   AS_COMMENT      xxx
*  5   AS_ICONBW       xxx
*  6   AS_ICONCOLOR    xxx
*  8   AS_FILEDATES    xxx         xxx       xxx         xxx
*  9   AS_FINDERINFO   xxx
* 10   AS_MACINFO      xxx
* 11   AS_PRODOSINFO               xxx
* 12   AS_MSDOSINFO                          xxx
* 13   AS_AFPNAME                                        xxx
* 14   AS_AFPINFO                                        xxx
* 15   AS_AFPDIRID                                       xxx
*/

/* 
	entry ID 1, data fork of file - arbitrary length octet string 
	entry ID 2, resource fork - arbitrary length opaque octet string;
              as created and managed by MacOS resource manager
	entry ID 3, file's name as created on home file system - arbitrary
              length octet string; usually short, printable ASCII
	entry ID 4, standard Macintosh comment - arbitrary length octet
              string; printable ASCII, claimed 200 chars or less

	This is probably a simple duplicate of the 128 octet bitmap
	stored as the 'ICON' resource or the icon element from an 'ICN#'
	resource.
*/

/* entry ID 5, standard Mac black and white icon */
struct ASICONBW {
   uint32_t bitrow[32]; /* 32 rows of 32 1-bit pixels */
};

/*
* entry ID 6, "standard" Macintosh color icon - several competing
*              color icons are defined.  Given the copyright dates
*
* With System 7, Apple introduced icon families.  They consist of:
*      large (32x32) B&W icon, 1-bit/pixel,    type 'ICN#',
*      small (16x16) B&W icon, 1-bit/pixel,    type 'ics#',
*      large (32x32) color icon, 4-bits/pixel, type 'icl4',
*      small (16x16) color icon, 4-bits/pixel, type 'ics4',
*      large (32x32) color icon, 8-bits/pixel, type 'icl8', and
*      small (16x16) color icon, 8-bits/pixel, type 'ics8'.
*/

/*
* Times are stored as a "signed number of seconds before of after
* 12:00 a.m. (midnight), January 1, 2000 Greenwich Mean Time (GMT).
* Applications must convert to their native date and time
* conventions." Any unknown entries are set to 0x80000000
* (earliest reasonable time).
*/

/* entry ID 8, file dates info */
struct ASFILEDATES {
	time_t create;	/* file creation date/time */
	time_t modify;	/* last modification date/time */
	time_t backup;	/* last backup date/time */
	time_t access;	/* last access date/time */
};

/* entry ID 9, Macintosh Finder info & extended info */
struct ASFINDERINFO {
	uint8_t valid_count; /* 0 means all subitems are valid */
	FINFO finfo;
	FXINFO fxinfo;
};

#define AS_PROTECTED    0x0002 /* protected bit */
#define AS_LOCKED       0x0001 /* locked bit */

/* entry ID 10, Macintosh file information */
struct ASMACINFO {
	uint8_t filler[3]; /* filler, currently all bits 0 */
	uint8_t attribute;
};

/*
* NOTE: ProDOS-16 and GS/OS use entire fields.  ProDOS-8 uses low
* order half of each item (low byte in access & filetype, low word
* in auxtype); remainder of each field should be zero filled.
*/

/* entry ID 11, ProDOS file information */
struct ASPRODOSINFO {
	uint16_t access;	/* access word */
	uint16_t filetype;	/* file type of original file */
	uint32_t auxtype;	/* auxiliary type of the orig file */
};

/*
* MS-DOS file attributes occupy 1 octet; since the Developer Note
* is unspecific, I've placed them in the low order portion of the
* field (based on example of other ASMacInfo & ASProdosInfo).
*/

/* entry ID 12, MS-DOS file information */
struct ASMSDOSINFO {
	uint8_t filler;	/* filler, currently all bits 0 */
	uint8_t attr;	/* _dos_getfileattr(), MS-DOS */
					/* interrupt 21h function 4300h */
};

#define AS_DOS_NORMAL   0x00 /* normal file (all bits clear) */
#define AS_DOS_READONLY 0x01 /* file is read-only */
#define AS_DOS_HIDDEN   0x02 /* hidden file (not shown by DIR) */
#define AS_DOS_SYSTEM   0x04 /* system file (not shown by DIR) */
#define AS_DOS_VOLID    0x08 /* volume label (only in root dir) */
#define AS_DOS_SUBDIR   0x10 /* file is a subdirectory */
#define AS_DOS_ARCHIVE  0x20 /* new or modified (needs backup) */

/*
* entry ID 13, short file name on AFP server - arbitrary length
*  octet string; usually printable ASCII starting with '!' (0x21)
*/

/* entry ID 12, AFP server file information */
struct ASAFPINFO {
   uint8_t filler[3];	/* filler, currently all bits 0 */
   uint8_t attr;		/* file attributes */
};

#define AS_AFP_INVISIBLE    0x01 /* file is invisible */
#define AS_AFP_MULTIUSER    0x02 /* simultaneous access allowed */
#define AS_AFP_SYSTEM       0x04 /* system file */
#define AS_AFP_BACKUPNEEDED 0x40 /* new or modified (needs backup) */

/* entry ID 15, AFP server directory ID */
struct ASAFPDIRID {
   uint32_t dirid; /* file's directory ID on AFP server */
};

struct ENTRY_DATA {
	uint32_t entry_id;
	void *pentry;
};

/* The format of an AppleSingle/AppleDouble header */
struct APPLEFILE {
   ASHEADER header;		/* AppleSingle header part */
   uint16_t count;
   ENTRY_DATA *pentries;	/* array of entry descriptors */
};

extern pack_result applefile_pull_file(EXT_PULL *, APPLEFILE *);
extern pack_result applefile_push_file(EXT_PUSH *, const APPLEFILE *);
