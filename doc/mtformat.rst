Message Transfer Format
=======================

The Gromox Mailbox Transfer format (GXMT) is our streaming-capable
serialization format for conveying a bundle of MAPI objects for the purpose of
interprocess communication.

Whereas a TNEF file only records one object, GXMT can record many, folders
included. GXMT is streamable; there are no forward references, so the stream
need not be buffered by a reader to resolve refs. Backreferences are typically
named properties and folders that were created as part of processing earlier
parts of a stream. Out of convenience of implementation, the mt2exm program
buffers one entire object at a time before acting on it.


Spec
====

All integers are to be in little-endian form.

* ``char magic[8] = "GXMT0004";``
  Magic fixed value to indicate the MT stream revision.
* ``uint32_t splice_flag;``
  Indicates whether the root object of this MT stream is to become a new folder
  in the target mailbox (0), or whether the objects in this stream are to be
  spliced (1) into preexisting folders of a mailbox.
* ``uint32_t public_store_flag;``
  Indicates whether this MT stream was generated from a private (0) or public
  store (1) and whether folder IDs appearing in ``target_nid`` use the magic
  values from the ``PRIVATE_FID_`` or ``PUBLIC_FID_`` sets for built-in
  folders.
* ``uint64_t fm_size;``
  Size in bytes for the folder map section that follows.
* Folder map:
	* ``uint64_t fm_entries;``
	  The number of entries in the folder map
	* Repeat *fm_entries* times:
		* ``uint32_t nid;``
		  Numeric identifier for the folder within the MT stream.
		* ``uint8_t create;``
		  Indicates that a new folder is to be created (1), or that a
		  mailbox's existing folder should be reused (0).
		* ``uint64_t target_nid;``
		  If ``create`` is 0, then ``target_nid`` specifies the
		  matching folder ID in the target mailbox to use. Magic values
		  to denote built-in folders exist, e.g. ``PRIVATE_FID_INBOX``
		  (13); cf. ``include/gromox/mapi_types.hpp`` for a list.
		* ``char name[];``
		  NUL-terminated folder name string for newly created folders.
* ``uint64_t np_size;``
  Size in bytes for the named property map section that follows.
* Named Property map:
	* ``uint64_t np_entries;``
	  Number of entries in the NP map
	* Repeat *np_entries* times:
		* ``uint32_t proptag;``
		  The named property's assigned proptag for the MT stream. The
		  high 16 bits convey the propid, the low 16 bits the proptype.
		  An MT writer may emit PT_UNSPECIFIED for the proptype to
		  signal that an MT reader shall mask/disregard proptypes
		  during propid-to-propid remapping. If an MT writer emits any
		  other proptype, the MT reader should only do propid-to-propid
		  translations if the proptype matches.
		* PROPERTY_NAME serialized struct

The remainder of the stream is a set of "instructions" (so to speak) to mt2exm
to create folders/messages in the target mailbox. Each packet/frame is:

* ``uint64_t obj_size;``
  Size in bytes for this frame.
  The obj_size value does not include obj_size's own field size.
* Frame:
	* ``uint32_t mapi_objtype;``
	  ``MAPI_FOLDER`` (3), ``MAPI_MESSAGE`` (5), ``MAPI_ATTACH`` (7), or a
	  named property (250).
	* ``uint32_t nid;``
	  A unique identifier for this object in the MT stream.
	  Value 0 is reserved and must not be used.
	* ``uint32_t parent_type;``
		* If mapi_objtype is MAPI_FOLDER, parent_type must be
		  MAPI_FOLDER or zero (0 only allowed if parent_fid does not
		  indicate a real parent).
		* If mapi_objtype is MAPI_MESSAGE, parent_type must be
		  MAPI_FOLDER, MAPI_ATTACH (7), or zero (0 only allowed if
		  parent_fid does not indicate a real parent)
		* If mapi_objtype is MAPI_ATTACH, parent_type must be
		  MAPI_MESSAGE.
		* If mapi_objtype is namedprop/250, parent_type is ignored.
		* Reader implementations are free to ignore this field if they
		  kept track of the parent object's type in another way.
		* Writer implementations must be truthful about the value.
	* ``uint64_t parent_fid;``
		* Parent object of a folder, message or attachment.
		* The value 0 is reserved.
		* The value 0xffffffffffffffff indicates an "unanchored"
		  message that does not belong to any particular folder.
	* For objtype MAPI_FOLDER, more fields:
		* TAGGED_PROPVAL serialized struct for properties
		* ``uint64_t acl_count;``
		* repeat for *acl_count*:
			* PERMISSION_DATA serialized struct
	* For objtype MAPI_MESSAGE:
		* MESSAGE_CONTENT serialized struct
		* NUL-terminated string for the RFC5322 representation
		* NUL-terminated string (reserved)
	* For objtype 250 (named property):
		* PROPERTY_NAME serialized struct
	* For other object types:
	  Illegal frame. A diagnostic message should be emitted. Discard this
	  frame. A reader implementation may choose to continue parsing at
	  the next frame (the ``obj_size`` field is helpful in knowing where
	  the next frame starts), or abort parsing altogether.


ATTACHMENT_CONTENT serialization
================================

* TPROPVAL_ARRAY serialized struct indicating the attachment properties
* ``uint8_t embedded;``
  Indicates whether a file attachment (0) or an embedded message (1) follows.
* If embedded != 0:
	* MESSAGE_CONTENT serialized struct for the message


ATTACHMENT_LIST serialization
=============================

* ``uint16_t atcount;``
  Number of attachments.
* Repeat *atcount* times:
	* ATTACHMENT_CONTENT serialized struct


MESSAGE_CONTENT serialization
=============================

* TPROPVAL_ARRAY serialized struct
* ``uint8_t have_rcpts;``
* if have_rcpts != 0:
	* TARRAY_SET serialized struct
* ``uint8_t have_attachments;``
* if have_attachments != 0:
	* ATTACHMENT_LIST serialized struct


PERMISSION_DATA serialization
=============================

* ``uint8_t flags;``
  For GXMT, this is always ``ROW_ADD`` (0).
* TAGGED_PROPVAL serialized struct usually containing
  ``PR_SMTP_ADDRESS`` and ``PR_MEMBER_RIGHTS`` properties


PROPERTY_NAME serialization
===========================

For the concept of Named Properties, see
https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/mapi-named-properties
.

* ``uint8_t kind;``: MNID_ID (0) or MNID_STRING (1).
* ``FLATUID guid;``
* if the kind is MNID_ID, more fields:
	* ``uint32_t lid;``
          The NP's LID= portion.
* if the kind is MNID_STRING:
	* ``uint8_t name_size;``
		* Allocation hint for parsers. Specifies the number of
		  subsequent bytes that make up the name, including the
		  trailing U+0000 codepoint.
		* Reader implementations are free to ignore this field.
		* Writer implementations must not underspecify the size.
	* ``char16_t name[];``
	  A run of UTF-16 codepoints that make up the name. A U+0000 codepoint
	  marks the authoritative end of the string.
* On any other kind: Illegal namedprop, consider aborting the parse.


TAGGED_PROPVAL serialization
============================

* ``uint32_t proptag;``
  Property tag, consisting of the property ID (propid) in the high 16 bits and
  the property type (proptype) in the low 16 bits.
* switch on proptype:
	* PT_UNSPECIFIED (0): a TYPED_PROPVAL serialized struct follows
	* PT_NULL (0x1): (no value)
	* PT_SHORT (0x2): a s16LE integer follows
	* PT_LONG (0x3): a s32LE integer follows
	* PT_FLOAT (0x4): a IEEE754 32-bit fp value follows
	* PT_DOUBLE (0x5): a IEEE754 64-bit fp value follows
	* PT_CURRENCY (0x6): a s64LE integer indicating a quantity in units of 1/10000.
	* PT_APPTIME (0x7): a IEEE754 64-bit fp value follows
	* PT_ERROR (0xa): a u32LE value indicating a MAPI error code;
	  doesn't normally occur in GXMT streams
	* PT_BOOLEAN (0xb): a uint8_t indicating false (0) or true (1). Writers
	  must not emit any other value.
	* PT_OBJECT (0xd): ...
	* PT_I8 (0x14): a s64LE integer
	* PT_STRING8 (0x1e): a C string terminated by NUL. Character set encoding is
	  not conveyed, so it should only use US-ASCII.
	* PT_UNICODE (0x1f): a UTF-16 string terminated by a U+0000 codepoint.
	* PT_SYSTIME (0x40): a s64LE integer indicating time since the NT
	  epoch (1601-01-01) in units of 100 nanoseconds
	* PT_CLSID (0x48): 16 bytes specifying a GUID
	* PT_SVREID (0xfb): SVREID serialized struct
	* PT_SRESTRICTION (0xfd): RESTRICTION serialized struct
	* PT_ACTIONS (0xfe): ACTIONS serialized struct
	* PT_BINARY (0x0102): BINARY serialized struct
	* PT_MV_SHORT (0x1002): SHORT_ARRAY serialized struct
	* PT_MV_LONG (0x1003): LONG_ARRAY serialized struct
	* PT_MV_FLOAT (0x1004): FLOAT_ARRAY serialized struct
	* PT_MV_DOUBLE (0x1005): DOUBLE_ARRAY serialized struct
	* PT_MV_CURRENCY (0x1006): LONGLONG_ARRAY serialized struct
	* PT_MV_APPTIME (0x1007): DOUBLE_ARRAY serialized struct
	* PT_MV_I8 (0x1014): LONGLONG_ARRAY serialized struct
	* PT_MV_STRING8 (0x101e): STRING_ARRAY serialized struct
	* PT_MV_UNICODE (0x101f): WSTRING_ARRAY serialized struct
	* PT_MV_SYSTIME (0x1040): LONGLONG_ARRAY serialized struct
	* PT_MV_CLSID (0x1048): GUID_ARRAY serialized struct
	* PT_MV_BINARY (0x1102): BINARY_ARRAY serialized struct


TARRAY_SET serialization
========================

TARRAY_SET is basically a MAPI table (properties x rows).

* ``uint32_t count;``
  Number of rows
* Repeat *count* times:
	* TPROPVAL_ARRAY serialized struct specifying the properties in this
	  row


TPROPVAL_ARRAY serialization
============================

* ``uint16_t propcount;``
* Repeat *propcount* times:
	* TAGGED_PROPVAL serialized struct specifying the proptag and value.


TYPED_PROPVAL serialization
===========================

TYPED_PROPVALs are normally used by MAPI tables to respond to columns with a
PT_UNSPECIFIED type. TYPED_PROPVALs are not believed to appear in GXMT streams
in practice, as any GXMT writer wishing to write out a TYPED_PROPVAL object
could just write a properly formatted TAGGED_PROPVAL object with merged proptag
value. Nevertheless, TYPED_PROPVALs are part of the current specification.

* ``uint16_t proptype;``
* TAGGED_PROPVAL serialized struct specifying the propid and value.
