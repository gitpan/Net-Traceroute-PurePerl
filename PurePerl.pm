package Net::Traceroute::PurePerl;

use vars qw(@ISA $VERSION $AUTOLOAD %net_traceroute_native_var);
use strict;
use warnings;
use Net::Traceroute;
use Net::RawIP qw(:pcap);
use Socket;

@ISA = qw(Net::Traceroute);
$VERSION = '0.02';

# used if we need to use alarm for pcap timeout
$SIG{ALRM} = sub { die "timeout" };

my @icmp_unreach_code = (		TRACEROUTE_UNREACH_NET,
					TRACEROUTE_UNREACH_HOST,
					TRACEROUTE_UNREACH_PROTO,
					0,
					TRACEROUTE_UNREACH_NEEDFRAG,
					TRACEROUTE_UNREACH_SRCFAIL, );

# set up allowed autoload attributes we need
my @net_traceroute_native_vars = qw(use_alarm);
for my $attr ( @net_traceroute_native_vars ) { $net_traceroute_native_var{$attr}++; } 

sub AUTOLOAD {
    my $self = shift;
    my $attr = $AUTOLOAD;
    $attr =~ s/.*:://;
    return unless $attr =~ /[^A-Z]/;  # skip DESTROY and all-cap methods
    warn "invalid attribute method: ->$attr()" unless $net_traceroute_native_var{$attr};
    $self->{$attr} = shift if @_;
    return $self->{$attr};
}

sub new {
    my $self = shift;
    my $type = ref($self) || $self;
    my %arg = @_;

    $self = bless {}, $type;

    # keep a loop from happening when calling super::new
    my $backend = delete $arg{'backend'};

    # used to get around the real traceroute running the trace
    my $host = delete $arg{'host'};

    # call the real traceroute new
    $self->init(%arg);

    # put our host back in
    $self->host($host)		if (defined $host);
    $self->max_ttl(30)		unless (defined $self->max_ttl); 
    $self->queries(3)		unless (defined $self->queries); 
    $self->base_port(33434)	unless (defined $self->base_port); 
    $self->query_timeout(5)		unless (defined $self->query_timeout); 
    $self->packetlen(40)		unless (defined $self->packetlen); 

    # 1 if we are seeming to hang on the call to pcap next
    # 0 if you are fine with out
    $self->use_alarm(1)		unless (defined $self->use_alarm); 

    return $self;
}
sub pretty_print {
    my $self = shift;

    print "traceroute to (" . $self->host . ") , ". $self->max_ttl ." hops max, "
	    . $self->packetlen ." byte packets\n";

    for (my $hop=1; $hop <= $self->hops; $hop++) {
	print "$hop)\t" . ( $self->hop_query_host($hop,0) || "???" ) . "\t";

	for (my $query=1; $query <= $self->hop_queries($hop); $query++) {
	    print $self->hop_query_time($hop, $query). " ms\t";

	}

	print $self->hop_query_stat($hop) ."\n";
   }

}

sub traceroute {
    my $self = shift;

    $self->debug_print(1, "Performing traceroute\n");
    warn "No host provided!" && return undef unless (defined $self->host);
    
    # release any old hop structure
    $self->_zero_hops();

    # what device do we use to get to host, and it's address
    my $device = rdev($self->host);
    my $device_addr = ${ifaddrlist()}{$device};
    $self->source_address( $device_addr ) unless (defined $self->source_address);

    # this is the packet we will send out
    my $packet = new Net::RawIP({udp=>{}});

    # these are reference packets
    my $icmp = new Net::RawIP({icmp=>{}});			  
    my $udp  = new Net::RawIP({udp=>{}});  

    # listen for incoming icmp dest unreachable and time exceeded messages
    my $filter="ip proto \\icmp and dst host ". $self->source_address . " and (icmp[0]==3 or icmp[0]==11)";
    my $pcap = $packet->pcapinit($device,$filter,1500,$self->query_timeout);

    # this is how far into a binary packet we need to look to get
    # past the Ethernet header
    my $offset = linkoffset($pcap);

    my ($last_reply_addr, $last_icmp_type, $last_icmp_code) = (0,0,0);

    my ($reply_addr, $icmp_type, $icmp_code, $icmp_data) = (0,0,0,0);
    my ($end) = (0);
  
    my ($start_time, $end_time, $done_time) = (0,0,0);

    my $data = "a" x ($self->packetlen - 28);

    # set up our packet
    $packet->set({ ip => {saddr=>$self->source_address, daddr=>$self->host, frag_off=>0, tos=>0, id=>$$},
		   udp=> {data=>$data}	});

    # for ecah hop
    for (my $hop=1;  $hop <= $self->max_ttl;	$hop++){
	$self->debug_print(1, "Starting hop $hop\n");

	# for each query on this hop
	for (my $query=1;   $query <= $self->queries;	$query++ ){
	    $self->debug_print(1, "Starting query $query for hop $hop\n");

	    # increment ports as we go
	    my $port = $self->base_port + $hop;

	    # set our new ports and keep up with the ttls
	    $packet->set( { ip => { ttl => $hop }, udp =>{ source => $port, dest => $port }   } ); 

	    # thar she goes!
	    $packet->send();

	    # now start the timer
	    $start_time = $end_time = timem();

	    my $answer = 0;

	    while ( (($end_time-$start_time) < $self->query_timeout) && ! $answer) {
	        $self->debug_print(5, "still no answer. checked time: " . ($end_time-$start_time) ."\n");

		my $h;

		# end this nightmare if we got dest unreachable messages last time
		$end = 1 if($last_icmp_type==3);

		$last_reply_addr=$last_icmp_type=$last_icmp_code=0;

		# this will hold our reply from the network... if there is one
		my $answer_packet;

		# if we have problems with pcap not timing out
		if ($self->use_alarm) {

		    # wait for a return packet not longer than timeout seconds.
		    eval {
		        alarm($self->query_timeout);
		        $answer_packet = &next($pcap, $h);
		        alarm(0);
		    };

		    # if we got a SIGALRM
		    if ($@) {

			# and it was due to a timeout, 
		        if ($@ =~ /timeout/) {
			    # no biggie here, this happens
			    $self->debug_print(1, "call to pcap next timed out\n");
		        } else {
			    # there was some other strange error
			    alarm(0);           # clear the still-pending alarm
			    $self->debug_print(1, "strnage error while waiting on pcap call: $@\n");
		        }
		    }

		} else {
		    # if pcap times out just right for you
		    $answer_packet = &next($pcap, $h);
		}

		# we have our answer or a time out, so stop the clock
		$end_time = timem();

		# if we got a real network reply
		if (defined $answer_packet) {

		    # set our icmp packet to the reply
		    $icmp->bset(substr($answer_packet, $offset));

		    # get data from it
		    ($reply_addr, $icmp_type, $icmp_code, $icmp_data) 
			    = $icmp->get({ip=>['saddr'],icmp=>['type','code','data']});    

		    # the data of the icmp packet is our original packet
		    #   here we are just verifying that we got the right reply
		    $udp->bset($icmp_data);
		    my ($reply_sport) = $udp->get({udp=>['source']});
		    
		    if($reply_sport eq $port){   
			$answer = 1;
			
			# save the reply for next round
			($last_reply_addr, $last_icmp_type, $last_icmp_code) 
			    = ($reply_addr, $icmp_type, $icmp_code);
		    }
		}
	    }
	
	    $done_time = ($end_time-$start_time);

	    # if we timed out
	    if ( ($end_time - $start_time) > $self->query_timeout ){
	        $self->_add_hop_query($hop, $query , TRACEROUTE_TIMEOUT, addr2name($last_reply_addr), 0 );

	    # if we got a dest unreachable, set the codes
	    } elsif ( ! dest_unreachable($last_icmp_type, $last_icmp_code) ) {
		$self->_add_hop_query($hop, $query , $icmp_unreach_code[$icmp_code], 
				    addr2name($last_reply_addr), 0 );

	    # else everything was good
	    } else {
		$self->_add_hop_query($hop, $query , TRACEROUTE_OK, 
				    addr2name($last_reply_addr), rtt_time($done_time) );
	    }
	}
    }
	return if $end;
}


# convert the addr returned by RawIP into human readable ip
sub addr2dot {
  sprintf("%u.%u.%u.%u",unpack "C4", pack "N1", shift);
}

# convert the addr returned by RawIP into human readable name or ip
sub addr2name {
    my $addr = shift;
    my $name  = (gethostbyaddr( pack("N",$addr), AF_INET) )[0] || addr2dot($addr);
    return $name;
}

sub rtt_time {
    my $ms = shift;
    return sprintf("%.2f", 1000 * $ms);
}

sub dest_unreachable { 
    my $type = shift;
    my $code = shift;

    return ( $type != 3 || ($type == 3 && $code == 3) );
}

1;

__END__
=head1 NAME

Net::Traceroute:PurePerl - traceroute(1) functionality in perl via raw sockets

=head1 SYNOPSIS

    use Net::Traceroute::PurePerl;

    my $t = new Net::Traceroute::PurePerl(
				backend => 'PurePerl', # this optional
				host    => 'www.openreach.com',
				debug   => 0,
				max_ttl => 12,
				timeout => 2,
				packetlen => 40,
				use_alarm => 1,
				);
    $t->traceroute;
    $t->pretty_print;


=head1 DESCRIPTION

This module implements traceroute(1) functionality for perl5.  
It allows you to trace the path IP packets take to a destination.  
It is implemented by using raw sockets to act just like the regular traceroute.
You must have Net::RawIP installed. 
You must also be root to use the raw sockets.


=head1 OVERVIEW

A new Net::Traceroute::PurePerl object must be created with the I<new> method.
This will not perform the traceroute immediately, unlike Net::Traceroute.
It will return a "template" object that can be used to set parameters for several subsequent traceroutes.

Methods are available for accessing information about a given
traceroute attempt.  There are also methods that view/modify the
options that are passed to the object's constructor.

To trace a route, UDP packets are sent with a small TTL (time-to-live)
field in an attempt to get intervening routers to generate ICMP
TIME_EXCEEDED messages.

=head1 CONSTRUCTOR AND CLONING

    $obj = Net::Traceroute::PurePerl->new([base_port	=> $base_port,]
				[debug		=> $debuglvl,]
				[max_ttl	=> $max_ttl,]
				[host		=> $host,]
				[queries	=> $queries,]
				[query_timeout	=> $query_timeout,]
				[timeout	=> $timeout,]
				[source_address	=> $srcaddr,]
				[packetlen	=> $packetlen,]
				[trace_program	=> $program,]
				[no_fragment	=> $nofrag,]);
				[use_alarm	=> $use_alarm,]);
    $frob = $obj->clone([options]);

This is the constructor for a new Net::Traceroute object.  
If given C<host>, it will NOT actually perform the traceroute.  
You MUST call the traceroute method later.

Given an existing Net::Traceroute object $obj as a template, you can
call $obj->clone() with the usual constructor parameters.  The same
rules apply about defining host; that is, traceroute will be run if it
is defined.  You can always pass host => undef to clone.

Possible options are:

B<host> - A host to traceroute to.  If you don't set this, you get a
Traceroute object with no traceroute data in it.  The module always
uses IP addresses internally and will attempt to lookup host names via
inet_aton.

B<base_port> - Base port number to use for the UDP queries.
Traceroute assumes that nothing is listening to port C<base_port> to
C<base_port + (nhops * nqueries - 1)>
where nhops is the number of hops required to reach the destination
address and nqueries is the number of queries per hop.  
Default is what the system traceroute uses (normally 33434)  
C<Traceroute>'s C<-p> option.

B<debuglvl> - A number indicating how verbose debug information should
be.  Please include debug=>9 output in bug reports.

B<max_ttl> - Maximum number of hops to try before giving up.  Default
is what the system traceroute uses (normally 30).  C<Traceroute>'s
C<-m> option.

B<queries> - Number of times to send a query for a given hop.
Defaults to whatever the system traceroute uses (3 for most
traceroutes).  C<Traceroute>'s C<-q> option.

B<query_timeout> - How many seconds to wait for a response to each
query sent.  Uses the system traceroute's default value of 5 if
unspecified.  C<Traceroute>'s C<-w> option.

B<timeout> - unused here

B<source_address> - Select the source address that traceroute wil use.

B<packetlen> - Length of packets to use.  Traceroute tries to make the
IP packet exactly this long.

B<trace_program> - unused here

B<no_fragment> - unused at the moment

B<use_alarm> - Used to make sure the queries timeout as needed.  
If your trace seems to hang with this set to 0, set it to 1 and you should be good to go.

=head1 METHODS

=over 4

=item traceroute

Run the traceroute.  
Will fill in the rest of the object for informational queries.

=back

=head2 Controlling traceroute invocation

Each of these methods return the current value of the option specified
by the corresponding constructor option.  They will set the object's
instance variable to the given value if one is provided.

Changing an instance variable will only affect newly performed
traceroutes.  Setting a different value on a traceroute object that
has already performed a trace has no effect.

See the constructor documentation for information about methods that
aren't documented here.

=over 4

=item base_port([PORT])

=item max_ttl([PORT])

=item queries([QUERIES])

=item query_timeout([TIMEOUT])

=item host([HOST])

=item source_address([SRC])

=item packetlen([LEN])

=item trace_program([PROGRAM])

=item use_alarm([0|1])

=back

=head2 Obtaining information about a Trace

These methods return information about a traceroute that has already
been performed.

Any of the methods in this section that return a count of something or
want an I<N>th type count to identify something employ one based
counting.

=over 4

=item pretty_print

Prints to stdout a traceroute-like text.

=item stat

Returns the status of a given traceroute object.  One of
TRACEROUTE_OK, TRACEROUTE_TIMEOUT, or TRACEROUTE_UNKNOWN (each defined
as an integer).  TRACEROUTE_OK will only be returned if the host was
actually reachable.

=item found

Returns 1 if the host was found, undef otherwise.

=item pathmtu

If your traceroute supports MTU discovery, this method will return the
MTU in some circumstances.  You must set no_fragment, and must use a
packetlen larger than the path mtu for this to be set.

=item hops

Returns the number of hops that it took to reach the host.

=item hop_queries(HOP)

Returns the number of queries that were sent for a given hop.  This
should normally be the same for every query.

=item hop_query_stat(HOP, QUERY)

Return the status of the given HOP's QUERY.  The return status can be
one of the following (each of these is actually an integer constant
function defined in Net::Traceroute's export list):

QUERY can be zero, in which case the first succesful query will be
returned.

=over 4

=item TRACEROUTE_OK

Reached the host, no problems.

=item TRACEROUTE_TIMEOUT

This query timed out.

=item TRACEROUTE_UNKNOWN

Your guess is as good as mine.  Shouldn't happen too often.

=item TRACEROUTE_UNREACH_NET

This hop returned an ICMP Network Unreachable.

=item TRACEROUTE_UNREACH_HOST

This hop returned an ICMP Host Unreachable.

=item TRACEROUTE_UNREACH_PROTO

This hop returned an ICMP Protocol unreachable.

=item TRACEROUTE_UNREACH_NEEDFRAG

Indicates that you can't reach this host without fragmenting your
packet further.  Shouldn't happen in regular use.

=item TRACEROUTE_UNREACH_SRCFAIL

A source routed packet was rejected for some reason.  Shouldn't happen.

=item TRACEROUTE_UNREACH_FILTER_PROHIB

A firewall or similar device has decreed that your traffic is
disallowed by administrative action.  Suspect sheer, raving paranoia.

=item TRACEROUTE_BSDBUG

The destination machine appears to exhibit the 4.[23]BSD time exceeded
bug.

=back

=item hop_query_host(HOP, QUERY)

Return the dotted quad IP address of the host that responded to HOP's
QUERY.

QUERY can be zero, in which case the first succesful query will be
returned.

=item hop_query_time(HOP, QUERY)

Return the round trip time associated with the given HOP's query.  If
your system's traceroute supports fractional second timing, so
will Net::Traceroute.

QUERY can be zero, in which case the first succesful query will be
returned.

=back

=head1 CLONING SUPPORT 



=head1 BUGS

I have not tested the cloning functions of Net::Traceroute::PurePerl.
It ought to work, but if not, BUG me.

This has not been tested on windows, so please let me know if it works there.

You must have Net::RawIP, because I'm too lazy to re-invent the wheel.  
As such, we have all the bugs that Net::RawIP has.

=head1 SEE ALSO

traceroute(1)

=head1 AUTHOR

Tom Scanlan <tscanlan@openreach.com> owner Net::Traceroute::PurePerl

Daniel Hagerty <hag@ai.mit.edu> owner of Net::Traceroute and input on this fella

=head1 COPYRIGHT

Go right ahead and copy it.  2002 Tom Scanlan.
Don't blame me for damages, just the bugs.

=cut
