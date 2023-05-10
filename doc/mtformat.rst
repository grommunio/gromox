Message Transfer Format
=======================

MT is meant for immediate consumption, not storage.
As such, it was not designed with endian-independent encoding.

* ``char magic[8] = "GXMT0003";``
  File identification.
* ``uint32_t splice_flag;``
  Whether the root object of this MT stream is a new folder (0),
  or whether the objects in this MT stream are to be spliced (1) into
  a preexisting mailbox's folders.
* ``uint32_t public_store_flag;``
  Whether this MT stream was generated from a private (0) or public store (1).
  This also defines the scope/meaning for ``folder_map.target_nid``.
* ``uint64_t fm_size;``
  Size in bytes for the folder map section that follows.
* Folder map:
	* ``uint64_t fm_entries;``
	  The number of entries in the folder map
	* Repeat for *fm_entries*:
		* ``uint32_t nid;``
		  Numeric identifier for the folder within the MT stream.
		* ``uint8_t create;``
		  Whether this folder needs to be created
		  (else, reuse folder specified by ``target_nid``)
		* ``uint64_t target_nid;``
		  Folder ID in exmdb space
		* ``char name[];``
		  NUL-terminated folder name string for creation
* ``uint64_t np_size;``
  Size in bytes for the named property map section that follows.
* Named Property map:
	* ``uint64_t np_entries;``
	  Number of entries in the NP map
	* repeat for *np_entries*:
		* ``uint32_t propid;``
		* PROPERTY_NAME serialized struct

The remainder of the stream is a set of "instructions" (so to speak) to mt2exm
to create folders/messages. Each packet/frame is:

* ``uint64_t obj_size;``
  Size in bytes for the frame that follows.
* Frame:
	* ``uint32_t mapi_objtype;``
	  ``MAPI_FOLDER`` (3), ``MAPI_MESSAGE`` (5), or 250 for a namedprop.
	* ``uint32_t nid;``
	  Folder ID (MAPI_FOLDER), Message ID (MAPI_MESSAGE), or propid
	  (namedprop)
	* ``uint32_t parent_type;``
	* ``uint64_t parent_fid;``
	  Parent folder ID.
	* For objtype MAPI_FOLDER:
		* TAGGED_PROPVAL serialized struct for properties
		* ``uint64_t acl_count;``
		* repeat for *acl_count*:
			* PERMISSION_DATA serialized struct
	* For objtype MAPI_MESSAGE:
		* MESSAGE_CONTENT serialized struct
	* For objtype 250 (named property):
		* PROPERTY_NAME serialized struct
