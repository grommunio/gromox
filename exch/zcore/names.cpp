// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <gromox/defs.h>
#include <gromox/zcore_rpc.hpp>
#include "common_util.h"

using namespace gromox;

#define EXP(s) zcore_callid::s
#define E(s) #s
static constexpr const char *zcore_rpc_names[] = {
	E(logon),
	E(unloadobject),
	E(openentry),
	E(openstoreentry),
	E(openabentry),
	E(resolvename),
	nullptr,
	E(getpermissions),
	E(modifypermissions),
	E(modifyrules),
	E(getabgal),
	E(loadstoretable),
	E(openstore),
	E(openprofilesec),
	E(loadhierarchytable),
	E(loadcontenttable),
	E(loadrecipienttable),
	nullptr,
	E(loadruletable),
	E(createmessage),
	E(deletemessages),
	E(copymessages),
	E(setreadflags),
	E(createfolder),
	E(deletefolder),
	E(emptyfolder),
	E(copyfolder),
	E(getstoreentryid),
	E(entryidfromsourcekey),
	E(storeadvise),
	E(unadvise),
	E(notifdequeue),
	E(queryrows),
	E(setcolumns),
	E(seekrow),
	E(sorttable),
	E(getrowcount),
	E(restricttable),
	E(findrow),
	E(createbookmark),
	E(freebookmark),
	E(getreceivefolder),
	E(modifyrecipients),
	E(submitmessage),
	E(loadattachmenttable),
	E(openattachment),
	E(createattachment),
	E(deleteattachment),
	E(setpropvals),
	E(getpropvals),
	E(deletepropvals),
	E(setmessagereadflag),
	E(openembedded),
	E(getnamedpropids),
	E(getpropnames),
	E(copyto),
	E(savechanges),
	E(hierarchysync),
	E(contentsync),
	E(configsync),
	E(statesync),
	E(syncmessagechange),
	E(syncfolderchange),
	E(syncreadstatechanges),
	E(syncdeletions),
	E(hierarchyimport),
	E(contentimport),
	E(configimport),
	E(stateimport),
	E(importmessage),
	E(importfolder),
	E(importdeletion),
	E(importreadstates),
	E(getsearchcriteria),
	E(setsearchcriteria),
	E(messagetorfc822),
	"rfc822tomessage(v1)",
	E(messagetoical),
	E(icaltomessage),
	E(messagetovcf),
	E(vcftomessage),
	E(uinfo),
	E(checksession),
	E(getuseravailability),
	E(setpasswd),
	E(linkmessage),
	E(rfc822tomessage),
	E(icaltomessage2),
	E(imtomessage2),
	E(essdn_to_username),
};
#undef E
#undef EXP

const char *zcore_rpc_idtoname(zcore_callid i)
{
	auto j = static_cast<uint8_t>(i);
	static_assert(arsizeof(zcore_rpc_names) == static_cast<uint8_t>(zcore_callid::essdn_to_username) + 1);
	const char *s = j < arsizeof(zcore_rpc_names) ? zcore_rpc_names[j] : nullptr;
	return znul(s);
}
