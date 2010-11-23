use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::Twitpic',
    AUTHOR              => 'htgc <htgc.dev@gmail.com>',
    VERSION_FROM        => 'lib/Net/Twitpic.pm',
    ABSTRACT_FROM       => 'lib/Net/Twitpic.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-Twitpic-*' },
);
