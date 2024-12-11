#pragma once
#include <string>
#include <gromox/range_set.hpp>
#include <gromox/xarray2.hpp>

enum {
	MIDB_RESULT_OK = 0,
	MIDB_NO_SERVER,
	MIDB_RDWR_ERROR,
	MIDB_RESULT_ERROR,
	/* server_enomem is conveyed via RESULT_ERROR + errnum=ENOMEM */
	MIDB_LOCAL_ENOMEM,
	MIDB_TOO_MANY_RESULTS,
};

enum {
	FLAG_RECENT   = 0x1,
	FLAG_ANSWERED = 0x2,
	FLAG_FLAGGED  = 0x4,
	FLAG_DELETED  = 0x8,
	FLAG_SEEN     = 0x10,
	FLAG_DRAFT    = 0x20,
	FLAG_LOADED   = 0x80,
};

struct MSG_UNIT {
	std::string file_name;
	size_t size = 0;
	bool b_deleted = false;
};

using enum_folder_t = std::pair<uint64_t, std::string>;

namespace midb_agent {

extern GX_EXPORT int list_mail(const char *path, const std::string &folder, std::vector<MSG_UNIT> &, int *num, uint64_t *size);
extern GX_EXPORT int delete_mail(const char *path, const std::string &folder, const std::vector<MSG_UNIT *> &);
extern GX_EXPORT int get_uid(const char *path, const std::string &folder, const std::string &mid, unsigned int *uid);
extern GX_EXPORT int summary_folder(const char *path, const std::string &folder, size_t *exists, size_t *recent, size_t *unseen, uint32_t *uidvalid, uint32_t *uidnext, int *perrno);
extern GX_EXPORT int make_folder(const char *path, const std::string &folder, int *perrno);
extern GX_EXPORT int remove_folder(const char *path, const std::string &folder, int *perrno);
extern GX_EXPORT int ping_mailbox(const char *path, int *perrno);
extern GX_EXPORT int rename_folder(const char *path, const std::string &src_name, const std::string &dst_name, int *perrno);
extern GX_EXPORT int subscribe_folder(const char *path, const std::string &folder, int *perrno);
extern GX_EXPORT int unsubscribe_folder(const char *path, const std::string &folder, int *perrno);
extern GX_EXPORT int enum_folders(const char *path, std::vector<enum_folder_t> &, int *perrno);
extern GX_EXPORT int enum_subscriptions(const char *path, std::vector<enum_folder_t> &, int *perrno);
extern GX_EXPORT int insert_mail(const char *path, const std::string &folder, const char *file_name, const char *flags_string, long time_stamp, int *perrno);
extern GX_EXPORT int remove_mail(const char *path, const std::string &folder, const std::vector<MITEM *> &, int *perrno);
extern GX_EXPORT int list_deleted(const char *path, const std::string &folder, XARRAY *, int *perrno);
extern GX_EXPORT int fetch_simple_uid(const char *path, const std::string &folder, const gromox::imap_seq_list &, XARRAY *, int *perrno);
extern GX_EXPORT int fetch_detail_uid(const char *path, const std::string &folder, const gromox::imap_seq_list &, XARRAY *, int *perrno);
extern GX_EXPORT int set_flags(const char *path, const std::string &folder, const std::string &mid, int flag_bits, int *perrno);
extern GX_EXPORT int unset_flags(const char *path, const std::string &folder, const std::string &mid, int flag_bits, int *perrno);
extern GX_EXPORT int get_flags(const char *path, const std::string &folder, const std::string &mid, int *pflag_bits, int *perrno);
extern GX_EXPORT int copy_mail(const char *path, const std::string &src_folder, const std::string &src_mid, const std::string &dst_folder, std::string &dst_mid, int *perrno);
extern GX_EXPORT int search(const char *path, const std::string &folder, const char *charset, int argc, char **argv, std::string &ret_buff, int *perrno);
extern GX_EXPORT int search_uid(const char *path, const std::string &folder, const char *charset, int argc, char **argv, std::string &ret_buff, int *perrno);

}
