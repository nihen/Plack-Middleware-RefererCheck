package Plack::Middleware::RefererCheck;

use strict;
use 5.008_001;
use parent qw(Plack::Middleware);
 
__PACKAGE__->mk_accessors(qw(host same_scheme error_app));
 
our $VERSION = '0.02';

sub call {
    my($self, $env) = @_;

    $self->_check($env) ? $self->app->($env) : $self->error_app ? $self->error_app->($env) : _default_error_app();
}

sub _check {
    my ( $self, $env ) = @_;

    return 1 if $env->{REQUEST_METHOD} ne 'POST';

    my $scheme = $self->same_scheme ? qr{\Q$env->{'psgi.url_scheme'}\E} : qr{https?};
    my $host = $self->host || $env->{HTTP_HOST};
        $host = qr{\Q$host\E};

    return $env->{HTTP_REFERER} =~ m{\A$scheme://$host(?:/|\Z)};
}

sub _default_error_app {
    return ['403', ['Content-Type' => 'text/plain', 'Content-Length' => 9], ['Forbidden']];
}
 
1;
 
__END__
 
=head1 NAME
 
Plack::Middleware::RefererCheck - check referer for defensive CSRF attack.
 
=head1 SYNOPSIS
 
  use Plack::Builder;

  builder {
      enable 'RefererCheck', host => 'www.example.com', same_scheme => 1, error_app => sub { [403, [], ['Forbidden']] };
      $app;
  };
 
  or more simply(host from $env->{HTTP_HOST} and same_scheme => 0)
  # this is vulnerabilly for DNS Rebinding
  builder {
      enable 'RefererCheck';
      $app;
  };


=head1 DESCRIPTION
 
Plack::Middleware::RefererCheck

=head1 CONFIGURATION

=over 4

=item host

Instead of using $env->{HTTP_HOST} if you set.

=item same_scheme

Check if you are setting "1" the same scheme.default: "0"

=item error_app

Is an PSGI-app that runs on errors.default: return 403 Forbidden app.

=back
 
=head1 AUTHOR
 
Masahiro Chiba

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
 
=head1 SEE ALSO
 
L<Plack::Middleware> L<Plack::Builder>
 
=cut
