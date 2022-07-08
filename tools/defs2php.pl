#!/usr/bin/perl
use strict;
use warnings;
my $mode = 0;
if (scalar(@ARGV) > 0 && $ARGV[0] eq "-t") { $mode = 1; shift(@ARGV); }
if (scalar(@ARGV) > 0 && $ARGV[0] eq "-e") { $mode = 2; shift(@ARGV); }
while (<>) {
	&proptag() if ($mode == 1 && m{^\s*(// )?(PR_\w+) = PROP_TAG\((\w+), (\S+)\)});
	&simpledef() if ($mode == 1 && m{^\s*(// )?(PidLid\w+) = (\w+),});
	&errcode() if ($mode == 2 && m{^\s+(// )?(ec\w+|[A-Z]{2}\w+) = ([^,]+),(.*)});
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
	my($key, $value) = ($2, $3);
	my @aliases = "$2 $4" =~ m{\b([A-Z]{2}\w*_[WEX]_\w+)}g;
	if (scalar(@aliases) == 0 && defined($key) && substr($key, 0, 2) eq "ec") {
		# ec* is the only name available for $value
		print "C($key, $value)\n";
		return;
	}
	for my $a (@aliases) {
		print "C($a, $value)\n";
	}
}

sub simpledef
{
	print "C($2, $3)\n";
}
