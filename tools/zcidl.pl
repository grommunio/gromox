#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
# This file is part of Gromox.
use Getopt::Long;
use strict;
use warnings;
our $gen_mode = "";
&Getopt::Long::Configure(qw(bundling));
&GetOptions(
	"client" => sub { $gen_mode = "CLN"; },
	"server" => sub { $gen_mode = "SDF"; },
);

if ($gen_mode eq "CLN") {
	print "#include <$_>\n" for qw(utility gromox/defs.h gromox/zcore_client.hpp gromox/zcore_rpc.hpp);
	print "#include \"$_\"\n" for qw(php.h);
}

while (<STDIN>) {
	next if (!m{^\s*ZCIDL\(\s*(\w+)\s*,\s*\((.*)\)\)});
	my($func, $iargs, $oargs, $iargf, $oargf) = ($1, $2, [], [], []);
	if ($iargs =~ s{^(.*),\s*IDLOUT\s+(.*)}{$1, $2}) {
		$iargs = $1;
		$oargf = [&split_argl($2)];
		$oargs = [&split_adcl(@$oargf)];
	}
	$iargf = [&split_argl($iargs)];
	$iargs = [&split_adcl(@$iargf)];
	my $rbsig = join(", ", @$iargf, @$oargf);

	if ($gen_mode eq "SDF") {
		print "case zcore_callid::$func: {\n";
		if (scalar(@$iargs) > 0) {
			print "\tauto &q = *static_cast<const zcreq_$func *>(q0);\n";
			if ($iargs->[0][0] eq "GUID" &&
			    $iargs->[0][1] eq "hsession") {
				print "\tdbg_hsession = q.hsession;\n";
			}
		}
		print "\tauto r1 = std::make_unique<zcresp_$func>();\n";
		if (scalar(@$oargs) > 0) {
			print "\tauto &r = *r1;\n";
		}
		print "\tr1->result = zs_$func(", join(", ",
			(map { my($type, $field) = @$_; "q.$field"; } @$iargs),
			(map { my($type, $field) = @$_; (substr($type, -1, 1) eq "&" ? "" : "&")."r.$field"; } @$oargs),
		), ");\n";
		print "\tr0 = std::move(r1);\n";
		print "\tbreak;\n}\n";
		next;
	}

	print "ec_error_t zclient_$func($rbsig)\n{\n";
	print "\tzcreq_$func q{};\n\tzcresp_$func r{};\n\n";
	print "\tq.call_id = zcore_callid::$func;\n";
	for (@$iargs) {
		my($type, $field) = @$_;
		if (substr($type, -1, 1) eq "*") {
			print "\tq.$field = deconst($field);\n";
		} else {
			print "\tq.$field = $field;\n";
		}
	}
	print "\tif (!zclient_do_rpc(&q, &r))\n\t\treturn ecRpcFailed;\n";
	if (scalar(@$oargs) > 0) {
		print "\tif (r.result != ecSuccess)\n\t\treturn r.result;\n";
	}
	for (@$oargs) {
		my($type, $field) = @$_;
		print "\t", (substr($type, -1, 1) eq "&" ? "" : "*"),
		      "$field = std::move(r.$field);\n";
	}
	print "\treturn r.result;\n}\n\n";
}

sub split_adcl { return map { [&fname($_)] } @_; }
sub split_argl { return map { $_ eq "" ? () : ($_) } split(qr{\s*,\s*}, shift(@_)); }
sub fname
{
	$_[0] =~ /(\s*(\w+)\s*)$/;
	my $type = substr($_[0], 0, -length($1));
	return ($type, $2);
}
