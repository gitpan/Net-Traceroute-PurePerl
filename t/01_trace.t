#!/usr/bin/perl

use strict;
use warnings;

BEGIN {
  $| = 1;
  if ($> and ($^O ne 'VMS')) {
    print "1..0 # skipped: Traceroute requires root privilege\n";
    exit 0;
  }
};

use Net::Traceroute::PurePerl;
use Test::More tests => 5;

sub DEBUG () { return 0 }

my $host = 'www.perl.org';
my $t    = "";

eval {
   $t = Net::Traceroute::PurePerl->new(
      host              => $host,
      debug             => DEBUG,
      first_hop         => 1,
      base_port         => 33434,
      max_ttl           => 15,
      query_timeout     => 3,
      queries           => 3,
      source_address    => '0.0.0.0',
      packetlen         => 40,
      protocol          => 'udp',
      concurrent_hops   => 6,
      device            => undef,
   );
};

ok(
      ref $t eq 'Net::Traceroute::PurePerl',
      'Object created successfully'
) or diag($@);

if ($t)
{

my $success;

eval {$success = $t->traceroute};

ok(
      defined $success,
      'Traceroute completed successfully'
);

$t->protocol('icmp');

my $success2;

eval {$success2 = $t->traceroute};

ok(
      defined $success2,
      'ICMP Traceroute completed successfully'
);

$t->protocol('notimplemented');
eval {$t->traceroute};

ok(
      $@ =~ /Parameter `protocol\'/,
      "Bad protocol detected successfully"
);

$t->protocol('icmp');
$t->host('badhost.x');
eval {$t->traceroute};

ok(
      $@ =~ /Could not resolve host/,
      "Bad host detected successfully"
);
}
else
{
   foreach (1 .. 4)
   {
      fail('Could not create trace object');
   }
}

