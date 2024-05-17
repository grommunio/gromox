#!/usr/bin/perl
# SPDX-License-Identifier: MIT
use strict;
use warnings;
my $dir = shift(@ARGV);
my $dsize = scalar(@ARGV) * 64;
my $ofs = 12 + $dsize;
print "PACK", pack("VV", 12, $dsize);
@ARGV = map { "$dir/$_" } @ARGV;
for (@ARGV) {
	my $n = $_;
	$n =~ s{^.*/}{};
	print pack("Z56VV", $n, $ofs, -s $_);
	$ofs += -s _;
}
print for <>;
