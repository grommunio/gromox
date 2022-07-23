#include <cstring>
#include <gromox/vcard.hpp>

int main()
{
	vcard C;
	auto &l = C.append_line("ADR");
	l.append_param("TYPE", "WORK");
	auto v = vcard_new_value();
	v->append_subval("HOME");
	v->append_subval("HOME2");
	l.append_value(v);
	v = vcard_new_value();
	v->append_subval("DO");
	v->append_subval("DO2");
	l.append_value(v);

	char buf[128000];
	C.serialize(buf, std::size(buf));
	printf("%s\n", buf);
	C.clear();
	C.retrieve_single(buf);
	C.serialize(buf, std::size(buf));
	printf("%s\n", buf);

	strcpy(buf, "BEGIN:VCARD\n\nEND:VCARD\n");
	C.retrieve_single(buf);
}
