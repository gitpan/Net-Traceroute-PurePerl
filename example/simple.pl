#!/usr/bin/perl

use strict;
use Net::Traceroute::PurePerl;
use Data::Dumper;

my $t = new Net::Traceroute::PurePerl(
			    host    => 'www.openreach.com',
			    debug   => 0,
			    max_ttl => 12,
			    timeout => 2,
			    );

$t->traceroute;
#print Data::Dumper->Dump([$t], [qw(t )]);
$t->pretty_print;

