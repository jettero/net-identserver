# vi:set syntax=perl:

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'	     	=> 'Net::IdentServer',
    'VERSION_FROM'	=> 'IdentServer.pm',
    'PREREQ_PM'     => { 
        'Net::Server::Fork'  => 0,
        'Net::Telnet'        => 0,
    },
);
