#!/usr/bin/perl

use strict;
use warnings;
my $provider = grep("-p", @ARGV);

print "#include <$_>\n" for qw(cstring gromox/exmdb_client.hpp gromox/exmdb_rpc.hpp);
if ($provider) {
	print "#include \"$_\"\n" for qw(common_util.h exmdb_client.h exmdb_ext.hpp);
	print "#include \"exmdb_server.h\"\n";
}
print "using namespace gromox;\n";

while (<STDIN>) {
	next if (!m{^\s*EXMIDL\(\s*(\w+)\s*,\s*\(const\s+char\s*\*dir(.*)\)\)});
	my($func, $iargs, $oargs, $iargf, $oargf) = ($1, $2, [], [], []);
	if ($iargs =~ s{^(.*),\s*IDLOUT\s+(.*)}{$1, $2}) {
		$iargs = $1;
		$oargf = [&split_argl($2)];
		$oargs = [&split_adcl(@$oargf)];
	}
	$iargf = [&split_argl($iargs)];
	$iargs = [&split_adcl(@$iargf)];
	my $rbsig = join(", ", "const char *dir", @$iargf, @$oargf);
	if ($provider) {
		my @anames = ("dir", map { $_->[1] } (@$iargs, @$oargs));
		print "BOOL exmdb_client_local::$func($rbsig)\n{\n";
		print "\tBOOL xb_private;\n\n";
		print "\tif (!exmdb_client_check_local(dir, &xb_private))\n";
		print "\t\treturn exmdb_client_remote::$func(".join(", ", @anames).");\n";
		print "\texmdb_server_build_env(EM_LOCAL | (xb_private ? EM_PRIVATE : 0), dir);\n";
		print "\tauto xbresult = exmdb_server_$func(".join(", ", @anames).");\n";
		print "\texmdb_server_free_environment();\n";
		print "\treturn xbresult;\n";
		print "}\n\n";
		next;
	}
	print "BOOL exmdb_client_remote::$func($rbsig)\n{\n";
	print "\tEXMDB_REQUEST request;\n\tEXMDB_RESPONSE response;\n";
	print "\n";
	print "\trequest.call_id = exmdb_callid::".lc($func).";\n";
	print "\trequest.dir = deconst(dir);\n";
	for (@$iargs) {
		my($type, $field) = @$_;
		if (substr($type, -1, 1) eq "*") {
			print "\trequest.payload.$func.$field = deconst($field);\n";
		} else {
			print "\trequest.payload.$func.$field = $field;\n";
		}
	}
	print "\tif (!exmdb_client_do_rpc(std::move(request), &response))\n\t\treturn false;\n";
	for (@$oargs) {
		my($type, $field) = @$_;
		print "\t*$field = response.payload.$func.$field;\n";
	}
	print "\treturn TRUE;\n}\n\n";
}

sub split_adcl { return map { [&fname($_)] } @_; }
sub split_argl { return map { $_ eq "" ? () : ($_) } split(qr{\s*,\s*}, shift(@_)); }
sub fname
{
	$_[0] =~ /(\s*(\w+)\s*)$/;
	my $type = substr($_[0], 0, -length($1));
	return ($type, $2);
}
