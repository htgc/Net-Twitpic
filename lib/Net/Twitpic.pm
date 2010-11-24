package Net::Twitpic;

use warnings;
use strict;
use Carp;

use version; our $VERSION = qv('0.0.4');

use Digest::HMAC_SHA1 qw/hmac_sha1/;
use WWW::Curl::Easy;
use WWW::Curl::Form;
use URI::Escape;

# Module implementation here

sub _url_encode {
    my $str = shift;
    $str = "" unless defined $str;
    if ($str =~ /[\x80-\xFF]/ and !utf8::is_utf8($str)) {
	   warn "Net::Twitpic warning: your message appears to contain some multi-byte characters that need to be decoded via Encode.pm or a PerlIO layer first.  This may result in an incorrect signature.";
    }
    return URI::Escape::uri_escape_utf8($str,'^\w.~-');
}

sub new {
	my $class = shift;
	my %args = @_;
	bless {
		api_key => [],
		consumer_token => [],
		consumer_secret => [],
		token => [],
		token_secret => [],
		%args
	}, $class;
}

for my $method ( qw/
	api_key
	consumer_secret
	consumer_key
	token
	token_secret/ ) {
	no strict 'refs';
	*{__PACKAGE__ . "::$method"} = sub {
		my $self = shift;
		$self->{$method} = shift if @_;
		return $self->{$method};
	}
}

sub _get_signature {
	my $self = shift;
	my %args = @_;
	my $key = _url_encode($self->{consumer_secret}) . '&' . _url_encode($self->{token_secret});
	my $base_str = 'GET&' . _url_encode('https://api.twitter.com/1/account/verify_credentials.json');
	$base_str .= '&';
	$base_str .= _url_encode('oauth_consumer_key') . '%3D' . _url_encode($self->{consumer_key}) . '%26';
	$base_str .= _url_encode('oauth_nonce') . '%3D' . _url_encode($args{nonce}) . '%26';
	$base_str .= _url_encode('oauth_signature_method') . '%3D' . _url_encode('HMAC-SHA1') . '%26';
	$base_str .= _url_encode('oauth_timestamp') . '%3D' . _url_encode($args{timestamp}) . '%26';
	$base_str .= _url_encode('oauth_token') . '%3D' . _url_encode($self->{token}) . '%26';
	$base_str .= _url_encode('oauth_version') . '%3D' . _url_encode('1.0');

	my $hmac = Digest::HMAC_SHA1->new( $key );
	$hmac->add( $base_str );
	return $hmac->b64digest . '%3D';
}

sub upload {
	my $self = shift;
	my %args = @_;
	my $message = $args{message} || '';
	my $media = $args{media} || '';
	my $timestamp = time;
	my $nonce = $timestamp ^ $$ ^ int(rand 2**32);

	my $curlf = WWW::Curl::Form->new;
	$curlf->formaddfile( $media, 'media', 'multipart/form-data' );
	$curlf->formadd( 'key', $self->{api_key} );
	$curlf->formadd( 'message', $message );

	my $auth_headers = [];
	my $templ = 'X-Verify-Credentials-Authorization: OAuth realm="http://api.twitter.com/",';
	$templ .= _url_encode('oauth_consumer_key') . '="' . _url_encode($self->{consumer_key}) . '",';
	$templ .= _url_encode('oauth_signature_method') . '="' . _url_encode('HMAC-SHA1') . '",';
	$templ .= _url_encode('oauth_token') . '="' . _url_encode($self->{token}) . '",';
	$templ .= _url_encode('oauth_timestamp') . '="' . _url_encode($timestamp) . '",';
	$templ .= _url_encode('oauth_nonce') . '="' . _url_encode($nonce) . '",';
	$templ .= _url_encode('oauth_version') . '="' . _url_encode('1.0') . '",';
	$templ .= _url_encode('oauth_signature') . '="' . _get_signature($self, timestamp => $timestamp, nonce => $nonce) . '"';

	push @$auth_headers, $templ;
	$templ = 'X-Auth-Service-Provider: "https://api.twitter.com/1/account/verify_credentials.json"';
	push @$auth_headers, $templ;

	my $curl = WWW::Curl::Easy->new;
	$curl->setopt( CURLOPT_CONNECTTIMEOUT, 30 );
	$curl->setopt( CURLOPT_HEADER, 0 );
	$curl->setopt( CURLOPT_URL, 'http://api.twitpic.com/2/upload.json' );
	$curl->setopt( CURLOPT_HTTPPOST, $curlf );
	$curl->setopt( CURLOPT_HTTPHEADER, $auth_headers );

	my $ret = $curl->perform;
	return $curl->seterror( $ret ) if $ret != 0;
	return $curl->getinfo(CURLINFO_HTTP_CODE);
}



1; # Magic true value required at end of module
__END__

=head1 NAME

Net::Twitpic - [Twitpic upload module using APIv2]


=head1 VERSION

This document describes Net::Twitpic version 0.0.4


=head1 SYNOPSIS

    use Net::Twitpic;

    my $twitpic = Net::Twitpic->new(
        consumer_key     => 'YOUR-CONSUMER-KEY',
        consumer_secret  => 'YOUR-CONSUMER-SECRET',
        token            => 'OAUTH-TOKEN',
        token_secret     => 'OAUTH-TOKEN-SECRET',
        api_key          => 'TWITPIC-API-KEY'
    );

    my $response = $twitpic->upload(
        message  => 'Hello',
        media    => '/file/to/path'
    );

=head1 DESCRIPTION

    Net::Twitpic is upload module for Twitpic using APIv2.
    Please refer about JSON response to E<lt>http://dev.twitpic.com/docs/2/upload/E<gt>

=head1 CONFIGURATION AND ENVIRONMENT

Net::Twitpic requires no configuration files or environment variables.

  Digest::HMAC_SHA1
  WWW::Curl::Easy
  WWW::Curl::Form
  URI::Escape

=head1 AUTHOR

htgc  C<< <htgc.dev@gmail.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2010, htgc C<< <togachiro@gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

