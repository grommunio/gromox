
property
	Blurry term; can either refer to proptag or propid, and depending on
	that context, may either be unique for some object O, or not.

propid, property identifier
	A 16-bit number used to identify a given property logically. propids
	below 0x8000 are fixed; e.g. the Subject is assigned 0x37. propids above
	0x8000 are dynamically assigned during the runtime of a program, cf.
	propname.

propname, property name
	A property identifier that includes a namespace GUID and a
	GUID-specific integer or string. This mechanism allows to have much
	more than 32767 properties defined, though only at most 32767 can be
	active at any one time for a program or a mail store.

proptag, property tag
	The property tag is an ORed combination of a propid and a proptype.
	Objects like folders and messages etc. have an associative array of
	proptags to values. This implies that a propid can occur multiple
	times — in general though, at most one per object.
	
proptype, property type
	A 16-bit number used to denote the semantics of the memory block that
	makes up a property's assigned value.
