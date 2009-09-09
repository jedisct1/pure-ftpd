#! /usr/bin/env perl

# This program checks the format strings of pure-ftpd's message files
# (C) 2001-2002 by Matthias Andree <matthias.andree@web.de>
# COPYING: Conditions as per the GNU General Public License v2.0

# $Id: messages_check.pl,v 1.2 2001/12/21 22:31:01 chrysalis Exp $

use Carp qw(verbose);	# get backtraces
use Parse::RecDescent;	# parser
use strict;		# need to define everything
use vars qw/ $debug /;	# global debug flag

$debug = 0;
#$::RD_TRACE=1;
$::RD_HINT=1;

# Grammar for message files (simple)
my $grammar = q`
<nocheck>

msgfile:	<rulevar: local $ident> 
		| <rulevar: local %fmts>
		| line(s) eofile
		{ {fmts=>\%fmts} }

line:		/^#define/ identifier arg

arg:		string(s)
arg:		identifier

format:		/%[-#0 +\'I]?\d*(\\.\d*)?(hh?|ll?|L|q|j|z|t)?[diouxXeEfFgGaAcspn%]/

identifier:	/[a-z][a-z0-9_]*/i
		| <error>

partstring:	'"' fmtatom(s?) '"'

string: 	partstring fold(?)
		| fold partstring
		| <error>

fold:		/\s*\\\\\n\s*/

fmtatom:	format
		| /([^%\"\\\\]|\\\\.)+/

eofile:		/^\Z/
`;

my $parser = new Parse::RecDescent($grammar);
defined $parser or die "Cannot set up parser.";

# read a message_*.h file and return a hash of (identifier, ARRAY_OF
# format strings) pairs

sub parse($ ) {
	# read file into a string
	open(F, "<$_[0]") or die "cannot open $_[0]: $!";
	my @a=<F>;
	my $text="@a";
	undef @a;

	# parse
	my $res = $parser->msgfile($text);
	die "Cannot parse" unless $res;

	return %{$res->{fmts}};
}

# compare two hashes (passed as references)
# arguments: master hash, slave hash, tag for error messages
# returns: 1 for error, 0 for success
sub check_hash($$$) {
	my ($h1, $h2, $fi) = @_;
	my $errorflag = 0;

	while (my ($h, $v) = each %$h1) {
		if (!defined $$h2{$h}) {
			print STDERR "$fi: ERROR: $h missing\n";
			$errorflag = 1;
		} else {
			my $s1 = join(",", @{$v});
			my $s2 = join(",", @{$$h2{$h}});
			if ($s1 ne $s2) {
				print STDERR "$fi: ERROR: format string mismatch for $h\n";
				$errorflag = 1;
			}
		}
		delete $$h1{$h};
		delete $$h2{$h};
	}
	if (keys %{$h2}) {
		print STDERR "$fi: ERROR: excess #defines: ",
			join(", ", sort keys %$h2), "\n";
		$errorflag = 1;
	}
	if (keys %{$h1}) {
		die "internal error, aborting";
	}
	return $errorflag;
}

# ----------------------------------------------------------------------
# - glob is the glob pattern for the localization headers
# - master is the localization header that is considered to be the most
#   current
my $glob   = 'messages_*.h';
my $master = 'messages_en.h';

# get file list
my @files = @ARGV > 0 ? @ARGV : grep { $_ ne $master } glob($glob);

# read master
my %h1 = parse($master) unless scalar @ARGV;

# check slaves
foreach my $f2 (@files) {
	print "Parsing $f2...\n";
	my %h2 = parse($f2);

	if (!check_hash({%h1}, {%h2}, $f2)) {
		print STDERR "$f2: ok\n";
	}
}
