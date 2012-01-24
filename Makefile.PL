use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'           => 'Net::Traceroute::PurePerl',
    'VERSION_FROM'   => 'lib/Net/Traceroute/PurePerl.pm',
    'PREREQ_PM'      => { 'Net::Traceroute' => '1.05' },
    'ABSTRACT_FROM'  => 'lib/Net/Traceroute/PurePerl.pm',
    'AUTHOR'         => 'John Kristoff <jtk@cpan.org>, Andrew Hoying <ahoying@cpan.org>',
    'LICENSE'        => 'perl',
);
