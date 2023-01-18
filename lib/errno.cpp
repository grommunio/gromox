#include <cstdio>
#include <gromox/defs.h>
#include <gromox/mapierr.hpp>

ec_error_t gxerr_to_hresult(gxerr_t e)
{
	switch (e) {
	case GXERR_SUCCESS: return ecSuccess;
	case GXERR_OVER_QUOTA: return MAPI_E_STORE_FULL;
	default: return ecError;
	}
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
	}
	thread_local char xbuf[32];
	snprintf(xbuf, gromox::arsizeof(xbuf), "Unknown error %xh", e);
	return xbuf;
#undef E
}
