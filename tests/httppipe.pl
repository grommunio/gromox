#!/usr/bin/perl

use Getopt::Long;
use IO::Poll;
use IO::Socket::IP;
use strict;
use warnings;
my $poll_wait = 0.4;
&Getopt::Long::Configure(qw(bundling));
&GetOptions("b" => sub { $poll_wait = undef; });
my $cgiuri = "POST /web/index2.php HTTP/1.1\r\n";
my $txturi = "POST /web/version.txt HTTP/1.1\r\n";
my $body_1 = "Content-Length: 1\r\n\r\na\r\n";
my $body_2 = "Content-Length: 2\r\n\r\nbc\r\n";
my $body_3 = "Transfer-Encoding: chunked\r\n\r\n3\r\nd\r\n0\r\n\r\n";
my $body_4 = "Transfer-Encoding: chunked\r\n\r\n4\r\nef\r\n0\r\n\r\n";
my @req = (
	"GET /x HTTP/1.1\r\n\r\nGET /web/version.txt HTTP/1.1\r\n\r\n",
	"$cgiuri$body_1$cgiuri$body_2",
	"$cgiuri$body_3$cgiuri$body_4",
	"$txturi$body_1$txturi$body_2",
	"$txturi$body_3$txturi$body_4",
);
my $xcnt = 0;
&split_req();
&multi_req();

sub split_req
{
	my $sock = IO::Socket::IP->new(
		Domain => AF_INET6,
		Type => SOCK_STREAM,
		Proto => "tcp",
		PeerPort => 80,
		PeerHost => "::",
	) || die "cannot open socket: $!";
	print "\e[1;41mCONN #", ++$xcnt, " out: >>\e[0m\n", "GET / HTTP/1.1\n", "\e[41m<<\e[0m\n";
	print "Press ENTER to send next fragment(s)\n";
	$sock->send("GET");
	<STDIN>;
	$sock->send(" /");
	<STDIN>;
	$sock->send(" HTTP/1.1\r\n\r\n");
	&xrecv($sock);
}

sub multi_req
{
	foreach my $req (@req) {
		my $sock = IO::Socket::IP->new(
			Domain => AF_INET6,
			Type => SOCK_STREAM,
			Proto => "tcp",
			PeerPort => 80,
			PeerHost => "::",
		) || die "cannot open socket: $!";
		print "\e[1;41mCONN #", ++$xcnt, " out: >>\e[0m\n", $req, "\e[41m<<\e[0m\n";
		$sock->send($req);
		&xrecv($sock);
	}
}

sub xrecv
{
	my $sock = shift @_;
	my $poll = IO::Poll->new();
	$poll->mask($sock, POLLIN | POLLERR | POLLHUP);
	while ($poll->poll($poll_wait) > 0) {
		my $buf;
		$sock->recv($buf, 1048576, 0);
		if (length($buf) == 0) {
			last;
		}
		print "\e[1;42mCONN #$xcnt in: >>\e[0m\n", $buf, "\e[42m<<\e[0m\n";
	}
}
