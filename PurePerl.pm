package Net::Traceroute::PurePerl;

use vars qw(@ISA $VERSION $AUTOLOAD %net_traceroute_native_var %protocols);
use strict;
use warnings;
use Net::Traceroute;
use Socket;
use Carp qw(carp croak);
use FileHandle;
use Time::HiRes qw(time);

@ISA = qw(Net::Traceroute);
$VERSION = '0.10_01';

use constant SO_BINDTODEVICE        => 25;   # from asm/socket.h
use constant IPPROTO_IP             => 0;    # from netinet/in.h

# Windows winsock2 uses 4 for IP_TTL instead of 2
use constant IP_TTL                 => ($^O eq "MSWin32") ? 4 : 2;

use constant IP_HEADERS             => 20;   # Length of IP headers
use constant ICMP_HEADERS           => 8;    # Length of ICMP headers
use constant UDP_HEADERS            => 8;    # Length of UDP headers

use constant IP_PROTOCOL            => 9;    # Position of protocol number

use constant UDP_DATA               => IP_HEADERS + UDP_HEADERS;
use constant ICMP_DATA              => IP_HEADERS + ICMP_HEADERS;

use constant UDP_SPORT              => IP_HEADERS + 0; # Position of sport
use constant UDP_DPORT              => IP_HEADERS + 2; # Position of dport

use constant ICMP_TYPE              => IP_HEADERS + 0; # Position of type
use constant ICMP_CODE              => IP_HEADERS + 2; # Position of code
use constant ICMP_ID                => IP_HEADERS + 4; # Position of ID
use constant ICMP_SEQ               => IP_HEADERS + 6; # Position of seq

use constant ICMP_PORT              => 0;    # ICMP has no port

use constant ICMP_TYPE_TIMEEXCEED   => 11;   # ICMP Type
use constant ICMP_TYPE_ECHO         => 8;    # ICMP Type
use constant ICMP_TYPE_UNREACHABLE  => 3;    # ICMP Type
use constant ICMP_TYPE_ECHOREPLY    => 0;    # ICMP Type

use constant ICMP_CODE_ECHO         => 0;    # ICMP Echo has no code

BEGIN
{
   if ($^O eq "MSWin32" and $^V eq v5.8.6)
   {
      $ENV{PERL_ALLOW_NON_IFS_LSP} = 1;
   }
}

%protocols = 
(
               'icmp'      => 1,
               'udp'       => 1,
);

my @icmp_unreach_code = 
(		
               TRACEROUTE_UNREACH_NET,
					TRACEROUTE_UNREACH_HOST,
					TRACEROUTE_UNREACH_PROTO,
					0,
					TRACEROUTE_UNREACH_NEEDFRAG,
					TRACEROUTE_UNREACH_SRCFAIL, 
);

# set up allowed autoload attributes we need
my @net_traceroute_native_vars = qw(use_alarm concurrent_hops
      protocol first_hop device);

for my $attr ( @net_traceroute_native_vars )
{
   $net_traceroute_native_var{$attr}++; 
}

sub AUTOLOAD 
{
   my $self = shift;
   my $attr = $AUTOLOAD;
   $attr =~ s/.*:://;
   return unless $attr =~ /[^A-Z]/;  # skip DESTROY and all-cap methods
   carp "invalid attribute method: ->$attr()" 
      unless $net_traceroute_native_var{$attr};
   $self->{$attr} = shift if @_;
   return $self->{$attr};
}

sub new 
{
   my $self = shift;
   my $type = ref($self) || $self;
   my %arg = @_;

   $self = bless {}, $type;

   # keep a loop from happening when calling super::new
   my $backend = delete $arg{'backend'};

   # used to get around the real traceroute running the trace
   my $host = delete $arg{'host'};

   # Old method to use ICMP for traceroutes, using `protocol' is preferred
   my $useicmp = delete $arg{'useicmp'};

   # call the real traceroute new
   $self->init(%arg);

   # Set protocol to ICMP if useicmp was set;
   if ($useicmp)
   {
      carp ("Protocol already set, useicmp is overriding")
         if (defined $self->protocol  and $self->protocol ne "icmp");
      $self->protocol('icmp') if ($useicmp);
   }

   # put our host back in
   $self->host($host)	      if (defined $host);
   $self->max_ttl(30)		   unless (defined $self->max_ttl); 
   $self->queries(3)		      unless (defined $self->queries);
   $self->base_port(33434)	   unless (defined $self->base_port); 
   $self->query_timeout(5)	   unless (defined $self->query_timeout); 
   $self->packetlen(40)		   unless (defined $self->packetlen); 
   $self->first_hop(1)        unless (defined $self->first_hop);
   $self->concurrent_hops(6)  unless (defined $self->concurrent_hops);
   
   # UDP is the UNIX default for traceroute
   $self->protocol('udp')  unless (defined $self->protocol);

   # Depreciated: we no longer use libpcap, so the alarm is no longer
   # required. Kept for backwards compatibility but not used.
   $self->use_alarm(0)		unless (defined $self->use_alarm); 

   $self->_validate();
   
   return $self;
}

sub init
{
   my $self = shift;
   my %arg  = @_;

   foreach my $var (@net_traceroute_native_vars)
   {
      if(defined($arg{$var})) {
         $self->$var($arg{$var});
      }
   }

   $self->SUPER::init(@_);
}

sub pretty_print 
{
   my $self = shift;

   print "traceroute to " . $self->host;
   print " (" . inet_ntoa($self->{'_destination'}) . "), ";
   print  $self->max_ttl . " hops max, " . $self->packetlen ." byte packets\n";

   my $lasthop = $self->first_hop + $self->hops - 1;
   
   for (my $hop=$self->first_hop; $hop <= $lasthop; $hop++)
   {
      my $lasthost = '';

	   printf '%2s ', $hop;

      if (not $self->hop_queries($hop))
      {
         print "error: no responses\n";
         next;
      }

      for (my $query=1; $query <= $self->hop_queries($hop); $query++) {
         my $host = $self->hop_query_host($hop,$query);
         if ($host and ( not $lasthost or $host ne $lasthost ))
         {
            printf "\n%2s ", $hop if ($lasthost and $host ne $lasthost);
            printf '%-15s ', $host;
            $lasthost = $host;
         }
         my $time = $self->hop_query_time($hop, $query);
         if (defined $time and $time > 0)
         {
            printf '%7s ms ', $time;
         }
         else
         {
            print "* ";
         }
	   }

      print "\n";
   }

   return;
}

sub traceroute 
{
   my $self = shift;

   $self->_validate();

   $self->debug_print(1, "Performing traceroute\n");
   carp "No host provided!" && return undef unless (defined $self->host);

   {
      my $destination = inet_aton($self->host);
      
      croak "Could not resolve host " . $self->host 
         unless (defined $destination);

      $self->{_destination} = $destination;
   }
    
   # release any old hop structure
   $self->_zero_hops();

   # Create the ICMP socket, used to send ICMP messages and receive ICMP errors
   # Under windows, the ICMP socket doesn't get the ICMP errors unless the
   # sending socket was ICMP, or the interface is in promiscuous mode, which 
   # is why ICMP is the only supported protocol under windows.
   my $icmpsocket = FileHandle->new();

   socket($icmpsocket, PF_INET, SOCK_RAW, getprotobyname('icmp')) ||
      croak("ICMP Socket error - $!");

   $self->debug_print(2, "Created ICMP socket to receive errors\n");

   $self->{'_icmp_socket'}    = $icmpsocket;
   $self->{'_trace_socket'}   = $self->_create_tracert_socket();

   my $success = $self->_run_traceroute();

   return $success;
}

# convert the addr returned by RawIP into human readable name or ip
sub addr2name 
{
   my $addr = shift;
   my $name  = (gethostbyaddr( pack("N",$addr), AF_INET) )[0] || addr2dot($addr);
   return $name;
}

sub rtt_time 
{
   my $ms = shift;
   return sprintf("%.2f", 1000 * $ms);
}

sub dest_unreachable 
{ 
   my $type = shift;
   my $code = shift;

   return ( $type != 3 || ($type == 3 && $code == 3) );
}


# Private functions

sub _validate
{
   my $self = shift;

   # Normalize values;

   $self->protocol(           lc $self->protocol);

   $self->max_ttl(            sprintf('%i',$self->max_ttl));
   $self->queries(            sprintf('%i',$self->queries));
   $self->base_port(          sprintf('%i',$self->base_port));
   $self->query_timeout(      sprintf('%i',$self->query_timeout));
   $self->packetlen(          sprintf('%i',$self->packetlen));
   $self->first_hop(          sprintf('%i',$self->first_hop));
   $self->concurrent_hops(    sprintf('%i',$self->concurrent_hops));

   # Check to see if values are sane

   croak "Parameter `protocol' value is not supported : " . $self->protocol 
      if (not exists $protocols{$self->protocol});

   croak "Parameter `first_hop' must be an integer between 1 and 255"
      if ($self->first_hop < 1 or $self->first_hop > 255);

   croak "Parameter `max_ttl' must be an integer between 1 and 255"
      if ($self->max_ttl < 1 or $self->max_ttl > 255);

   croak "Parameter `base_port' must be an integer between 1 and 65280"
      if ($self->base_port < 1 or $self->base_port > 65280);

   croak "Parameter `packetlen' must be an integer between 40 and 1492"
      if ($self->packetlen < 40 or $self->packetlen > 1492);

   croak "Parameter `first_hop' must be less than or equal to `max_ttl'"
      if ($self->first_hop > $self->max_ttl);

   croak "parameter `queries' must be an interger between 1 and 255"
      if ($self->queries < 1 or $self->queries > 255);
   
   croak "parameter `concurrent_hops' must be an interger between 1 and 255"
      if ($self->concurrent_hops < 1 or $self->concurrent_hops > 255);

   return;
}

sub _run_traceroute
{
   my $self = shift;

   my (  $end,
         $endhop,
         $stop,
         $sentpackets,
         $currenthop,
         $currentquery,
         $nexttimeout,
         $timeout,
         $rbits,
         $nfound,
         %packets,
         %pktids,
      );

   $stop = $end = $endhop = $sentpackets = 0;

   %packets = ();
   %pktids  = ();

   $currenthop    = $self->first_hop;
   $currentquery  = 0;

   $rbits   = "";
   vec($rbits,$self->{'_icmp_socket'}->fileno(), 1) = 1;

   while (not $stop)
   {
      while (scalar keys %packets < $self->concurrent_hops and 
            $currenthop <= $self->max_ttl and
            not select((my $rout = $rbits),undef,undef,0))
      {
         $sentpackets++;
         $self->debug_print(1,"Sending packet $currenthop $currentquery\n");
         my $start_time = $self->_send_packet($currenthop,$currentquery);
         my $id         = $self->{'_last_id'};
         my $localport  = $self->{'_local_port'};

         $packets{$sentpackets} =  
         {
               'id'        => $id,
               'hop'       => $currenthop,
               'query'     => $currentquery,
               'localport' => $localport,
               'starttime' => $start_time,
               'timeout'   => $start_time+$self->query_timeout,
         };

         $pktids{$id} = $sentpackets;

         $nexttimeout = $packets{$sentpackets}{'timeout'} 
            unless ($nexttimeout);

         $currentquery = ($currentquery + 1) % $self->queries;
         if ($currentquery == 0)
         {
            $currenthop++;
         }
      }
      $timeout = 0;
      if (keys %packets == $self->concurrent_hops)
      {
         $timeout = $nexttimeout - time;
         $timeout = .01 if ($timeout > .1);
      }
      $nfound  = select((my $rout = $rbits),undef,undef,$timeout);
      while ($nfound and keys %packets)
      {
         my (  $recv_msg,
               $from_saddr,
               $from_port,
               $from_ip,
               $from_id,
               $from_proto,
               $from_type,
               $from_code,
               $icmp_data,
               $local_port,
               $end_time,
               $last_hop,
            );

         $end_time   = time;

         $from_saddr = recv($self->{'_icmp_socket'},$recv_msg,1500,0);
         if (defined $from_saddr)
         {
            ($from_port,$from_ip)   = sockaddr_in($from_saddr);
            $from_ip                = inet_ntoa($from_ip);
            $self->debug_print(1,"Received packet from $from_ip\n");
         }
         else
         {
            $self->debug_print(1,"No packet?\n");
            $nfound = 0;
            last;
         }

         $from_proto = unpack('C',substr($recv_msg,IP_PROTOCOL,1));

         if ($from_proto != getprotobyname('icmp'))
         {
            my $protoname = getprotobynumber($from_proto);
            $self->debug_print(1,"Packet not ICMP $from_proto($protoname)\n");
            last;
         }

         ($from_type,$from_code) = unpack('CC',substr($recv_msg,ICMP_TYPE,2));
         $icmp_data              = substr($recv_msg,ICMP_DATA);

         if (not $icmp_data)
         {
            $self->debug_print(1,
                  "No data in packet ($from_type,$from_code)\n");
            last;
         }

         if (  $from_type == ICMP_TYPE_TIMEEXCEED or
               $from_type == ICMP_TYPE_UNREACHABLE or
               ($self->protocol eq "icmp" and 
                  $from_type == ICMP_TYPE_ECHOREPLY) )
         {

            if ($self->protocol eq 'udp')
            {
               $local_port    = unpack('n',substr($icmp_data,UDP_SPORT,2));
               $from_id       = unpack('n',substr($icmp_data,UDP_DPORT,2));

               $last_hop      = ($from_type == ICMP_TYPE_UNREACHABLE) ? 1 : 0;
            }
            elsif ($self->protocol eq 'icmp')
            {
               if ($from_type == ICMP_TYPE_ECHOREPLY)
               {
                  my $icmp_id = unpack('n',substr($recv_msg,ICMP_ID,2));
                  last unless ($icmp_id == $$);

                  my $seq     = unpack('n',substr($recv_msg,ICMP_SEQ,2));
                  $from_id    = $seq; # Reusing the same variable name
                  $last_hop   = 1;;

                  $self->debug_print(1,"Got echo reply\n");
               }
               else
               {
                  my $icmp_id = unpack('n',substr($icmp_data,ICMP_ID,2));
                  return unless ($icmp_id == $$);

                  my $ptype   = unpack('C',substr($icmp_data,ICMP_TYPE,1));
                  my $pseq    = unpack('n',substr($icmp_data,ICMP_SEQ,2));
                  if ($ptype eq ICMP_TYPE_ECHO)
                  {
                     $from_id = $pseq; # Reusing the variable
                  }
               }
            }
         }

         if ($from_ip and $from_id)
         {
            my $id = $pktids{$from_id};
            if ($packets{$id}{'id'} == $from_id)
            {
               last if ($self->protocol eq 'udp' and 
                     $packets{$id}{'localport'} != $local_port);

               my $total_time = $end_time - $packets{$id}{'starttime'};
               my $hop        = $packets{$id}{'hop'};
               my $query      = $packets{$id}{'query'};

               if (not $endhop or $hop <= $endhop)
               {

                  if ($last_hop)
                  {
                     $end++;
                     $endhop = $hop;
                  }

                  $self->debug_print(1,"Recieved response for $hop $query\n");
                  $self->_add_hop_query($hop, $query+1, TRACEROUTE_OK, 
                        $from_ip, rtt_time($total_time) );
               }
               delete $packets{$id};
            }
         }
         $nfound  = select((my $rout = $rbits),undef,undef,0);
      }
      if (keys %packets and $nexttimeout < time)
      {
         undef $nexttimeout;
         
         foreach my $id (sort keys %packets)
         {
            if ($packets{$id}{'timeout'} < time)
            {
               my $hop        = $packets{$id}{'hop'};
               my $query      = $packets{$id}{'query'};

               if ($endhop and $hop == $endhop)
               {
                  $end++;
               }
               elsif ($endhop and $hop > $endhop)
               {
                  delete $packets{$id};
                  next;
               }

               $self->debug_print(1,"Timeout for $hop $query\n");
	            $self->_add_hop_query($hop, $query+1, TRACEROUTE_TIMEOUT, 
                     "", 0 );
               
               delete $packets{$id};
            }
            elsif (not defined $nexttimeout)
            {
               $nexttimeout = $packets{$id}{'timeout'};
               last;
            }
         }
      }

      # Check if it is time to stop the looping
      if ($currenthop > $self->max_ttl and not keys %packets)
      {
         $self->debug_print(1,"No more packets, last hop\n");
         $stop = 1;
      }
      elsif ($end == $self->queries)
      {
         $self->debug_print(1,"Reached last hop\n");
         $end  = 1;
         $stop = 1;
      }

      # Looping
   }

   return $end;
}

# _create_tracert_socket reuses the ICMP socket already created for
# icmp traceroutes, or creates a new socket. It then binds the socket
# to the user defined devices and source address if provided and returns
# the created socket.

sub _create_tracert_socket
{
   my $self = shift;
   my $socket;
   
   if ($self->protocol eq "icmp")
   {
      $socket = $self->{'_icmp_socket'};
   }
   elsif ($self->protocol eq "udp")
   {
      $socket     = FileHandle->new();
      
      socket($socket, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or
         croak "UDP Socket creation error - $!";

      $self->debug_print(2,"Created UDP socket");
   }

   if ($self->device)
   {
      setsockopt($socket, SOL_SOCKET, SO_BINDTODEVICE(), 
         pack('Z*', $self->device)) or 
            croak "error binding to ". $self->device ." - $!";

      $self->debug_print(2,"Bound socket to " . $self->device . "\n");
   }

   if ($self->source_address and $self->source_address ne '0.0.0.0')
   {
      $self->_bind($socket);
   }

   return $socket;
}

# _bind binds a sockets to a local source address so all packets originate
# from that IP.

sub _bind
{
   my $self    = shift;
   my $socket  = shift;

   my $ip = inet_aton($self->source_address);

   croak "Nonexistant local address ". $self->source_address 
      unless (defined $ip);

   CORE::bind($socket, sockaddr_in(0,$ip)) or
      croak "Error binding to ".$self->source_address.", $!";

   $self->debug_print(2,"Bound socket to " . $self->source_address . "\n");

   return;
}

sub _send_packet
{
   my $self          = shift;
   my ($hop,$query)  = @_;

   if ($self->protocol eq "icmp")
   {
      my $seq = ($hop-1) * $self->queries + $query + 1;
      $self->_send_icmp_packet($seq,$hop);
      $self->{'_last_id'} = $seq;
   }
   elsif ($self->protocol eq "udp")
   {
      my $dport = $self->base_port + ($hop-1) * $self->queries + $query;
      $self->_send_udp_packet($dport,$hop);
      $self->{'_last_id'} = $dport;
   }

   return time;
}

sub _send_icmp_packet
{
   my $self             = shift;
   my ($seq,$hop)       = @_;
   
   my $saddr            = $self->_connect(ICMP_PORT,$hop);
   my $data             = 'a' x ($self->packetlen - ICMP_DATA);

   my ($pkt, $chksum)   = (0,0);

   # Create packet twice, once without checksum, once with it
   foreach (1 .. 2)
   {
      $pkt     = pack('CC n3 A*',
                        ICMP_TYPE_ECHO,   # Type
                        ICMP_CODE_ECHO,   # Code
                        $chksum,          # Checksum
                        $$,               # ID (pid)
                        $seq,             # Sequence
                        $data,            # Data
                     );
      
      $chksum  = $self->_checksum($pkt) unless ($chksum);
   }

   send($self->{'_trace_socket'}, $pkt, 0, $saddr);

   return;
}

sub _send_udp_packet
{
   my $self          = shift;
   my ($dport,$hop)  = @_;
   
   my $saddr         = $self->_connect($dport,$hop);
   my $data          = 'a' x ($self->packetlen - UDP_DATA);

   $self->_connect($dport,$hop);

   send($self->{'_trace_socket'}, $data, 0);

   return;
}

sub _connect
{
   my $self          = shift;
   my ($port,$hop)   = @_;

   my $socket_addr   = sockaddr_in($port,$self->{_destination});
   
   if ($self->protocol eq 'udp')
   {
      CORE::connect($self->{'_trace_socket'},$socket_addr);
      $self->debug_print(2,"Connected to " . $self->host . "\n");
   }

   setsockopt($self->{'_trace_socket'}, IPPROTO_IP, IP_TTL, pack('C',$hop));
   $self->debug_print(2,"Set TTL to $hop\n");

   if ($self->protocol eq 'udp')
   {
      my $localaddr                    = getsockname($self->{'_trace_socket'});
      my ($lport,undef)                = sockaddr_in($localaddr);
      $self->{'_local_port'}           = $lport;
   }

   return ($self->protocol eq 'icmp') ? $socket_addr : undef;
}

# Lifted verbatum from Net::Ping 2.31
# Description:  Do a checksum on the message.  Basically sum all of
# the short words and fold the high order bits into the low order bits.

sub _checksum
{
   my $self = shift;
   my $msg = shift;

   my (  $len_msg,       # Length of the message
         $num_short,     # The number of short words in the message
         $short,         # One short word
         $chk            # The checksum
      );

   $len_msg    = length($msg);
   $num_short  = int($len_msg / 2);
   $chk        = 0;
   foreach $short (unpack("n$num_short", $msg))
   {
      $chk += $short;
   }                                           # Add the odd byte in
   $chk += (unpack("C", substr($msg, $len_msg - 1, 1)) << 8) if $len_msg % 2;
   $chk = ($chk >> 16) + ($chk & 0xffff);      # Fold high into low
   return(~(($chk >> 16) + $chk) & 0xffff);    # Again and complement
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
