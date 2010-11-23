use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Net::Twitpic',
    license             => 'perl',
    dist_author         => 'htgc <htgc.dev@gmail.com>',
    dist_version_from   => 'lib/Net/Twitpic.pm',
    requires => {
        'Digest::HMAC_SHA1',
        'WWW::Curl::Easy',
        'WWW::Curl::Form',
        'URI::Escape',
        'Test::More' => 0,
        'version'    => 0,
    },
    add_to_cleanup      => [ 'Net-Twitpic-*' ],
);

$builder->create_build_script();
