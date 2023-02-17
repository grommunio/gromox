#include <cstdio>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapierr.hpp>

static const char *mapi_errname(unsigned int e)
{
#define E(s) case (s): return #s;
	switch(e) {
	E(ecSuccess)
	E(ecUnknownUser)
	E(ecServerOOM)
	E(ecLoginPerm)
	E(ecNotSearchFolder)
	E(ecNoReceiveFolder)
	E(ecInvalidRecips)
	E(ecWrongServer)
	E(ecBufferTooSmall)
	E(ecSearchFolderScopeViolation)
	case ecRpcFormat: return "ecRpcFormat/ecNetwork";
	E(ecNullObject)
	E(ecQuotaExceeded)
	E(ecMaxAttachmentExceeded)
	E(ecSendAsDenied)
	E(ecNotExpanded)
	E(ecNotCollapsed)
	E(ecDstNullObject)
	E(ecMsgCycle)
	E(ecTooManyRecips)
	E(RPC_X_BAD_STUB_DATA)
	E(ecRejected)
	E(MAPI_W_NO_SERVICE)
	E(ecWarnWithErrors)
	E(MAPI_W_CANCEL_MESSAGE)
	E(SYNC_W_CLIENT_CHANGE_NEWER)
	E(ecInterfaceNotSupported)
	E(ecError)
	E(STG_E_ACCESSDENIED)
	E(StreamSeekError)
	E(STG_E_INVALIDPARAMETER)
	E(ecStreamSizeError)
	E(ecNotSupported)
	E(ecInvalidObject)
	E(ecObjectModified)
	E(ecObjectDeleted)
	E(ecInsufficientResrc)
	E(ecNotFound)
	E(ecLoginFailure)
	E(ecUnableToAbort)
	E(ecRpcFailed)
	E(ecTooComplex)
	E(ecComputed)
	E(MAPI_E_UNKNOWN_CPID)
	E(MAPI_E_UNKNOWN_LCID)
	E(ecTooBig)
	E(MAPI_E_DECLINE_COPY)
	E(ecTableTooBig)
	E(ecInvalidBookmark)
	E(ecNotInQueue)
	E(ecDuplicateName)
	E(ecNotInitialized)
	E(MAPI_E_NO_RECIPIENTS)
	E(ecRootFolder)
	E(MAPI_E_STORE_FULL)
	E(EC_EXCEEDED_SIZE)
	E(ecAmbiguousRecip)
	E(SYNC_E_OBJECT_DELETED)
	E(SYNC_E_IGNORE)
	E(SYNC_E_CONFLICT)
	E(SYNC_E_NO_PARENT)
	E(ecNPQuotaExceeded)
	E(NotImplemented)
	E(ecAccessDenied)
	E(ecMAPIOOM)
	E(ecInvalidParam)
	default: {
		thread_local char xbuf[32];
		snprintf(xbuf, std::size(xbuf), "%xh", e);
		return xbuf;
	}
	}
#undef E
}

const char *mapi_errname_r(unsigned int e, char *b, size_t bz)
{
	HX_strlcpy(b, mapi_errname(e), bz);
	return b;
}

const char *mapi_strerror(unsigned int e)
{
	// STG = storage
#define E(v, s) case v: return s;
	switch (e) {
	E(ecSuccess, "The operation succeeded")
	E(ecUnknownUser, "User is unknown to the system")
	E(ecServerOOM, "Server could not allocate memory")
	E(ecLoginPerm, "This user does not have access rights to the mailbox")
	E(ecNotSearchFolder, "The operation is valid only on a search folder")
	E(ecNoReceiveFolder, "No receive folder is available")
	E(ecInvalidRecips, "No valid recipients set on the message")
	E(ecWrongServer, "The server does not host the user's mailbox database")
	E(ecBufferTooSmall, "A buffer passed to this function is not big enough")
	E(ecSearchFolderScopeViolation, "Attempted to perform a recursive search on a search folder")
	E(ecRpcFormat, "A badly formatted RPC buffer was detected")
	E(ecNullObject, "An object handle reference in the RPC buffer could not be resolved")
	E(ecQuotaExceeded, "The operation failed because it would have exceeded a resource quota")
	E(ecMaxAttachmentExceeded, "The maximum number of message attachments has been exceeded")
	E(ecNotExpanded, "Error in expanding or collapsing rows in a categorized view")
	E(ecNotCollapsed, "Error in expanding or collapsing rows in a categorized view")
	E(ecDstNullObject, "The RPC buffer contains a destination object handle that could not be resolved to a Server object.")
	E(ecMsgCycle, "The source message contains the destination message and cannot be attached to it")
	E(ecTooManyRecips, "A hard limit on the number of recipients per message was exceeded")
	E(RPC_X_BAD_STUB_DATA, "RPC_X_BAD_STUB_DATA")
	E(ecRejected, "The operation was rejected")
	E(ecWarnWithErrors, "A request involving multiple properties failed for one or more individual properties, while succeeding overall")
	E(SYNC_W_CLIENT_CHANGE_NEWER, "In a change conflict, the client has the more recent change.")
	E(ecError, "The operation failed for an unspecified reason")
	E(STG_E_ACCESSDENIED, "Insufficient access rights to perform the operation")
	E(STG_E_INVALIDPARAMETER, "Invalid parameter passed to a IStorage/IStream operation")
	E(ecStreamSizeError, "The maximum size for the object was reached")
	E(StreamSeekError, "Tried to seek to offset before the start or beyond the max stream size of 2^31")
	E(ecNotSupported, "The server does not support this method call")
	E(ecInvalidObject, "A method call was made using a reference to an object that has been destroyed or is not in a viable state")
	E(ecObjectModified, "Change commit failed because the object was changed separately")
	E(ecObjectDeleted, "Change commit suppressed because the object was deleted on the server")
	E(ecInsufficientResrc, "Not enough of an unspecified resource was available to complete the operation")
	E(ecNotFound, "The requested object could not be found at the server")
	E(ecLoginFailure, "Client unable to log on to the server")
	E(ecUnableToAbort, "The operation cannot be aborted")
	E(ecRpcFailed, "An operation was unsuccessful because of a problem with network operations or services./The RPC was rejected for an unspecified reason.")
	E(ecTooComplex, "The operation requested is too complex for the server to handle")
	E(MAPI_E_UNKNOWN_CPID, "Unknown codepage ID")
	E(MAPI_E_UNKNOWN_LCID, "Unknown locale ID")
	E(ecTooBig, "The result set of the operation is too big for the server to return")
	E(MAPI_E_DECLINE_COPY, "The server cannot copy the object, possibly due to cross-server copy")
	E(ecTableTooBig, "The table is too big for the requested operation to complete")
	E(ecInvalidBookmark, "The bookmark passed to a table operation was not created on the same table")
	E(ecNotInQueue, "The message is no longer in the spooler queue of the message store")
	E(ecDuplicateName, "A folder or item cannot be created because one with the same name or other criteria already exists.")
	E(ecNotInitialized, "The subsystem is not ready")
	E(ecRootFolder, "A folder move or copy operation would create a cycle")
	E(EC_EXCEEDED_SIZE, "The message size exceeds the configured size limit")
	E(ecAmbiguousRecip, "An unresolved recipient matches more than one directory entry")
	E(SYNC_E_IGNORE, "A sync error occurred, but can be ignored, e.g. superseded change")
	E(SYNC_E_CONFLICT, "Conflicting changes to an object have been detected")
	E(SYNC_E_NO_PARENT, "The parent folder could not be found")
	E(NotImplemented, "Function is not implemented")
	E(ecAccessDenied, "Insufficient access rights to perform the operation")
	E(ecMAPIOOM, "Not enough memory was available to complete the operation")
	E(ecInvalidParam, "An invalid parameter was passed to a function or remote procedure call")
	E(ecInterfaceNotSupported, "MAPI interface not supported")
	E(ecInvalidEntryId, "Invalid EntryID")
	E(ecCorruptData, "There is an internal inconsistency in a database, or in a complex property value")
	E(MAPI_E_UNCONFIGURED, "MAPI_E_UNCONFIGURED")
	E(MAPI_E_FAILONEPROVIDER, "MAPI_E_FAILONEPROVIDER")
	E(MAPI_E_PASSWORD_CHANGE_REQUIRED, "Password change is required")
	E(MAPI_E_PASSWORD_EXPIRED, "Password has expired")
	E(MAPI_E_INVALID_WORKSTATION_ACCOUNT, "Invalid workstation account")
	E(ecTimeSkew, "The operation failed due to clock skew between servers")
	E(MAPI_E_ACCOUNT_DISABLED, "Account is disabled")
	E(MAPI_E_END_OF_SESSION, "The server session has been destroyed, possibly by a server restart")
	E(MAPI_E_UNKNOWN_ENTRYID, "The EntryID passed to OpenEntry was created by a different MAPI provider")
	E(ecTableEmpty, "A table essential to the operation is empty")
	E(MAPI_E_NO_RECIPIENTS, "A message cannot be sent because it has no recipients")
	E(MAPI_E_STORE_FULL, "Store is full")
	default: {
		thread_local char xbuf[40];
		snprintf(xbuf, sizeof(xbuf), "Unknown MAPI error code %xh", e);
		return xbuf;
	}
	}
#undef E
}
