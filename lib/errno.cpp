#include <cstdio>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

const uint8_t muidStoreWrap[16] =
	/* {10bba138-e505-1a10-a1bb-08002b2a56c2} */
	{0x38, 0xA1, 0xBB, 0x10, 0x05, 0xE5, 0x10, 0x1A,
	0xA1, 0xBB, 0x08, 0x00, 0x2B, 0x2A, 0x56, 0xC2};
const uint8_t g_muidStorePrivate[16] =
	/* {20fa551b-66aa-cd11-9bc8-00aa002fc45a} */
	{0x1B, 0x55, 0xFA, 0x20, 0xAA, 0x66, 0x11, 0xCD,
	0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
const uint8_t g_muidStorePublic[16] =
	/* {1002831c-66aa-cd11-9bc8-00aa002fc45a} */
	{0x1C, 0x83, 0x02, 0x10, 0xAA, 0x66, 0x11, 0xCD,
	0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
const uint8_t muidEMSAB[16] =
	/* {c840a7dc-42c0-1a10-b4b9-08002b2fe182} */
	{0xDC, 0xA7, 0x40, 0xC8, 0xC0, 0x42, 0x10, 0x1A,
	0xB4, 0xB9, 0x08, 0x00, 0x2B, 0x2F, 0xE1, 0x82};
const uint8_t pbLongTermNonPrivateGuid[16] =
	/* {9073441a-66aa-cd11-9bc8-00aa002fc45a} */
	{0x1A, 0x44, 0x73, 0x90, 0xAA, 0x66, 0x11, 0xCD,
	0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
const uint8_t muidOOP[16] =
	/* {a41f2b81-a3be-1910-9d6e-00dd010f5402} */
	{0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19,
	0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02};

unsigned int gxerr_to_hresult(gxerr_t e)
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
	E(StreamSeekError, "Tried to seek to offset before the start or beyond the max stream size of 2^31")
	E(ecNotSupported, "The server does not support this method call")
	E(ecInvalidObject, "A method call was made using a reference to an object that has been destroyed or is not in a viable state")
	E(ecObjectModified, "Change commit failed because the object was changed separately")
	E(ecInsufficientResrc, "Not enough of an unspecified resource was available to complete the operation")
	E(ecNotFound, "The requested object could not be found at the server")
	E(ecLoginFailure, "Client unable to log on to the server")
	E(ecUnableToAbort, "The operation cannot be aborted")
	E(ecRpcFailed, "ecRpcFailed")
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
	E(MAPI_E_FOLDER_CYCLE, "A folder move or copy operation would create a cycle")
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
