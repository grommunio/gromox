#!/usr/bin/perl

use Getopt::Long;
use strict;
use warnings;
our $gen_mode;
&Getopt::Long::Configure(qw(bundling));
&GetOptions(
	"c" => sub { $gen_mode = "CLN"; },
	"d" => sub { $gen_mode = "SDF"; },
	"p" => sub { $gen_mode = "SDP"; },
);

if ($gen_mode eq "CLN" || $gen_mode eq "SDP") {
	print "#include <$_>\n" for qw(cstring utility gromox/exmdb_client.hpp gromox/exmdb_rpc.hpp);
	if ($gen_mode eq "SDP") {
		print "#include <$_>\n" for qw(gromox/exmdb_common_util.hpp gromox/exmdb_ext.hpp gromox/exmdb_provider_client.hpp gromox/exmdb_server.hpp);
	}
	print "using namespace gromox;\n";
}

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

	if ($gen_mode eq "SDP") {
		my @anames = ("dir", map { $_->[1] } (@$iargs, @$oargs));
		print "BOOL exmdb_client_local::$func($rbsig)\n{\n";
		print "\tBOOL xb_private;\n\n";
		print "\tif (!exmdb_client_check_local(dir, &xb_private))\n";
		print "\t\treturn exmdb_client_remote::$func(".join(", ", @anames).");\n";
		print "\texmdb_server::build_env(EM_LOCAL | (xb_private ? EM_PRIVATE : 0), dir);\n";
		print "\tauto xbresult = exmdb_server::$func(".join(", ", @anames).");\n";
		print "\texmdb_server::free_env();\n";
		print "\treturn xbresult;\n";
		print "}\n\n";
		next;
	}
	if ($gen_mode eq "SDF") {
		print "case exmdb_callid::$func: {\n";
		if (scalar(@$iargs) > 0) {
			print "\tauto &q = *static_cast<const exreq_$func *>(q0);\n";
		}
		print "\tauto r1 = std::make_unique<exresp_$func>();\n";
		if (scalar(@$oargs) > 0) {
			print "\tauto &r = *r1;\n";
		}
		print "\tauto ret = exmdb_server::$func(", join(", ", "q0->dir",
			(map { my($type, $field) = @$_; (substr($type, -1, 1) eq "&" ? "*" : "")."q.$field"; } @$iargs),
			(map { my($type, $field) = @$_; (substr($type, -1, 1) eq "&" ? "" : "&")."r.$field"; } @$oargs),
		), ");\n";
		print "\tr0 = std::move(r1);\n";
		print "\treturn ret;\n}\n";
		next;
	}

	print "BOOL exmdb_client_remote::$func($rbsig)\n{\n";
	print "\texreq_$func q{};\n\texresp_$func r{};\n";
	print "\n";
	print "\tq.call_id = exmdb_callid::$func;\n";
	print "\tq.dir = deconst(dir);\n";
	for (@$iargs) {
		my($type, $field) = @$_;
		if (substr($type, -1, 1) eq "*") {
			print "\tq.$field = deconst($field);\n";
		} elsif (substr($type, -1, 1) eq "&") {
			# struct members should continue to use a pointer,
			# because refs are so awkward to assign (more so during
			# deserialization than with serialization)
			print "\tq.$field = deconst(&$field);\n";
		} else {
			print "\tq.$field = $field;\n";
		}
	}
	print "\tif (!exmdb_client_do_rpc(&q, &r))\n\t\treturn false;\n";
	for (@$oargs) {
		my($type, $field) = @$_;
		print "\t", (substr($type, -1, 1) eq "&" ? "" : "*"),
		      "$field = std::move(r.$field);\n";
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
