use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::Traceroute::PurePerl',
    'VERSION_FROM'	=> 'PurePerl.pm', # finds $VERSION
    'PREREQ_PM'		=> { Net::RawIP => 0.09,
			     Net::Traceroute => 1.05 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      ( AUTHOR     => 'Tom Scanlan <tscanlan@openreach.com>') : ()),
);
