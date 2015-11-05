package HTTP::Cookies::PhantomJS;

use strict;
use HTTP::Cookies;

our @ISA = 'HTTP::Cookies';
our $VERSION = '0.01';

use constant MAGIC => 'cookies="@Variant(\0\0\0\x7f\0\0\0\x16QList<QNetworkCookie>\0\0\0\0\x1';

sub load {
	my $self = shift;
	my $file = shift || $self->{'file'} || return;
	
	open my $fh, $file or return;
	<$fh>; # omit header
	my $data = <$fh>;
	close $fh;
	unless (substr($data, 0, length(MAGIC), '') eq MAGIC) {
		warn "$file does not seem to contain cookies";
		return;
	}
	
	1;
}

sub as_string {

}

sub save {

}

1;
