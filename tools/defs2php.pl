#!/usr/bin/perl
use strict;
use warnings;
while (<>) {
	&proptag() if (m{^\s*(// )?(PR_\w+) = PROP_TAG\((\w+), (\S+)\)});
	&errcode() if (m{^\s+(// )?(ec\w+|MAPI_\w+) = ([^,]+),(.*)});
}

sub proptag
{
	my $t;
	if ($3 eq "PT_NULL") { $t = 0; }
	elsif ($3 eq "PT_ACTIONS") { $t = 0xfe; }
	elsif ($3 eq "PT_BINARY") { $t = 0x102; }
	elsif ($3 eq "PT_BOOLEAN") { $t = 0xb; }
	elsif ($3 eq "PT_CLSID") { $t = 0x48; }
	elsif ($3 eq "PT_I8") { $t = 0x14; }
	elsif ($3 eq "PT_LONG") { $t = 0x3; }
	elsif ($3 eq "PT_MV_BINARY") { $t = 0x1102; }
	elsif ($3 eq "PT_MV_LONG") { $t = 0x1003; }
	elsif ($3 eq "PT_MV_STRING8") { $t = 0x101e; }
	elsif ($3 eq "PT_MV_UNICODE") { $t = 0x101e; } # like PT_UNICODE
	elsif ($3 eq "PT_OBJECT") { $t = 0xd; }
	elsif ($3 eq "PT_SHORT") { $t = 0x2; }
	elsif ($3 eq "PT_SRESTRICTION") { $t = 0xfd; }
	elsif ($3 eq "PT_STRING8") { $t = 0x1e; }
	elsif ($3 eq "PT_SVREID") { $t = 0xfb; }
	elsif ($3 eq "PT_SYSTIME") { $t = 0x40; }
	elsif ($3 eq "PT_UNICODE") { $t = 0x1e; } # php_mapi always operates in non-wide mode (w/UTF-8)
	else { die "Unknown $3"; }
	printf("C(%s, 0x%08x)\n", $2, hex($4) << 16 | $t);
}

sub errcode
{
	my($value, $aliases) = ($3, $4);
	printf("C(%s, %s)\n", $2, $value);
	while ($aliases =~ m{\b(ec\w+|MAPI_\w+)}g) {
		printf("C(%s, %s)\n", $&, $value);
	}
}
