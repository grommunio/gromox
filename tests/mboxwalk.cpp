// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
/* Example program how to obtain hierarchy table (folder list) and content table (message list / summary) */
#include <cstdio>
#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>

using namespace gromox;

static char *g_storedir;

static std::string readable_pathname(const char *in)
{
	std::string out;
	while (*in != '\0') {
		if (in[0] == '\xef' && in[1] == '\xbf' && in[2] == '\xbe') {
			out += '\\';
			in += 3;
		} else {
			out += *in++;
		}
	}
	return out;
}

static int do_message(const TPROPVAL_ARRAY &row, unsigned int depth)
{
	auto msg_id = row.get<const uint64_t>(PidTagMid);
	auto subject = row.get<const char>(PR_SUBJECT); /* limited to 255/510 chars */

	printf("%-*s", depth * 4, "");
	printf("msg %llu: \"%s\"\n",
		static_cast<unsigned long long>(rop_util_get_gc_value(*msg_id)), znul(subject));

	/*
	 * Table cells have a value length limit. If there is potential
	 * truncation (strlen(x) >= 255), then:
	 *
	 * - A table value should only be used for _displaying_.
	 *   It should not be stored or be used for data processing that
	 *   requires the full value.
	 *
	 * - Obtain the complete value with another call, like so:
	 */
	static constexpr proptag_t qtags1[] = {PR_SUBJECT, PR_SUBJECT_A};
	static constexpr PROPTAG_ARRAY qtags = {std::size(qtags1), deconst(qtags1)};
	TPROPVAL_ARRAY values{};
	if (!exmdb_client->get_message_properties(g_storedir, nullptr, CP_UTF8,
	    *msg_id, &qtags, &values)) {
		printf("get_msg_props RPC failed\n");
		return -1;
	}
	/*
	 * In Windows/MSMAPI, values of PT_UNICODE properties (such
	 * as PR_SUBJECT/PR_SUBJECT_W) are encoded as wchar_t. In the
	 * exmdb protocol, the encoding for PT_UNICODE is always
	 * UTF-8. [So if your virtual terminal does not have the
	 * right combination set, this printf call will output some
	 * garbage on umlauts/etc.]
	 */
	subject = values.get<const char>(PR_SUBJECT);
	printf("%-*sPR_SUBJECT: %s\n", depth * 4, "", subject ? subject : "(nullptr)");

	/*
	 * The values of PT_STRING8 properties (PR_SUBJECT_A) are
	 * encoded whatever codepage is requested, e.g. `CP_UTF8` above.
	 *
	 * Because everything on Linux is UTF-8 these days and
	 * PT_UNICODE serves the need just fine, not much thought was
	 * given to the use of codepages, and you may see `CP_ACP`
	 * instead in the source code too.
	 */
	subject = values.get<const char>(PR_SUBJECT_A);
	printf("%-*sPR_SUBJECT_A: %s\n", depth * 4, "", subject ? subject : "(nullptr)");

	/*
	 * In the following, as an example, we obtain the full message instead
	 * (complete with attachments etc.):
	 */
	MESSAGE_CONTENT *content = nullptr;
	if (!exmdb_client->read_message(g_storedir, nullptr, CP_ACP,
	    *msg_id, &content)) {
		printf("read_message RPC failed\n");
		return -1;
	}
	auto cleanup_0 = HX::make_scope_exit([&]() { message_content_free(content); });
	subject = content->proplist.get<const char>(PR_SUBJECT);
	printf("%-*sPR_SUBJECT (full msg): %s\n", depth * 4, "", subject ? subject : "(nullptr)");
	subject = content->proplist.get<const char>(PR_SUBJECT_A);
	printf("%-*sPR_SUBJECT_A (full msg): %s\n", depth * 4, "", subject ? subject : "(nullptr)");

	return 0;
}

static int do_folder(const TPROPVAL_ARRAY &row)
{
	auto depth     = row.get<const uint32_t>(PR_DEPTH);
	auto folder_id = row.get<const uint64_t>(PidTagFolderId);
	auto name      = row.get<const char>(PR_DISPLAY_NAME);
	auto pathname  = row.get<const char>(PR_FOLDER_PATHNAME);

	printf("%-*s", static_cast<int>(*depth * 4), "");
	printf("folder %llu: \"%s\" (%s)\n",
		static_cast<unsigned long long>(rop_util_get_gc_value(*folder_id)),
		znul(name),
		readable_pathname(pathname).c_str());


	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_content_table(g_storedir, CP_ACP, *folder_id,
	    nullptr, 0, nullptr, nullptr, &table_id, &row_count))
		return -EIO;
	auto cleanup_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(g_storedir, table_id); });


	static constexpr proptag_t tags1[] = {PidTagMid, PR_SUBJECT};
	static constexpr PROPTAG_ARRAY tags = {std::size(tags1), deconst(tags1)};
	TARRAY_SET tset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &tags, 0, row_count, &tset)) {
		fprintf(stderr, "exm: query_table RPC failed\n");
		return -1;
	}
	for (size_t i = 0; i < tset.count; ++i) {
		auto ret = do_message(*tset.pparray[i], *depth + 1);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int do_mbox()
{
	uint32_t table_id = 0, row_num = 0;
	/*
	 * This does not return the root entry itself, just its subordinates.
	 * Might want to refine later.
	 */
	auto root_fid = rop_util_make_eid_ex(1, PRIVATE_FID_ROOT);
	if (!exmdb_client->load_hierarchy_table(g_storedir, root_fid,
	    nullptr, TABLE_FLAG_DEPTH | TABLE_FLAG_NONOTIFICATIONS,
	    nullptr, &table_id, &row_num)) {
		fprintf(stderr, "exm: load_hierarchy_table RPC failed\n");
		return -1;
	}
	auto cleanup_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(g_storedir, table_id); });

	static constexpr proptag_t tags1[] = {PidTagFolderId, PR_DEPTH, PR_DISPLAY_NAME, PR_FOLDER_PATHNAME};
	static constexpr PROPTAG_ARRAY tags = {std::size(tags1), deconst(tags1)};
	TARRAY_SET tset{};
	if (!exmdb_client->query_table(g_storedir, nullptr, CP_ACP, table_id,
	    &tags, 0, row_num, &tset)) {
		fprintf(stderr, "exm: query_table RPC failed\n");
		return -1;
	}
	for (size_t i = 0; i < tset.count; ++i) {
		auto ret = do_folder(*tset.pparray[i]);
		if (ret != 0)
			return ret;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s MBOXDIR\n", argv[0]);
		return EXIT_FAILURE;
	}

	exmdb_client.emplace(1, 0);
	auto cleanup_0 = HX::make_scope_exit([]() { exmdb_client.reset(); });
	if (exmdb_client_run(PKGSYSCONFDIR) != 0)
		return EXIT_FAILURE;

	g_storedir = argv[1];
	return do_mbox() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
