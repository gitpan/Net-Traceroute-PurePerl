use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'		=> 'Net::Traceroute::PurePerl',
    'VERSION_FROM'	=> 'lib/Net/Traceroute/PurePerl.pm',
    'PREREQ_PM'		=> { Net::Traceroute => 1.05 },
    ($] >= 5.005 ?      ## Add these new keywords supported since 5.005
      ('ABSTRACT_FROM'  => 'lib/Net/Traceroute/PurePerl.pm', # retrieve abstract from module
       'AUTHOR'         => 'John Kristoff <jtk@cpan.org>, Andrew Hoying <ahoying@cpan.org>') : () ),
);
