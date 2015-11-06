package HTTP::Cookies::PhantomJS;

use strict;
use HTTP::Cookies;
use HTTP::Response;
use HTTP::Request;

our @ISA = 'HTTP::Cookies';
our $VERSION = '0.01';

use constant MAGIC => 'cookies="@Variant(\0\0\0\x7f\0\0\0\x16QList<QNetworkCookie>\0\0\0\0\x1';
my %ESCAPES = (
	'b'  => "\b",
	'f'  => "\f",
	'n'  => "\n",
	'r'  => "\r",
	't'  => "\t",
	'\\' => '\\',
);

sub _read_length_block {
	my $str_ref = shift;
	
	my $bytes;
	for (1..4) {
		my $c = substr($$str_ref, 0, 1, '');
		if ($c ne '\\') {
			$bytes .= sprintf '%x', ord($c);
			next;
		}
		
		$c = substr($$str_ref, 0, 1, '');
		if ($c ne 'x') {
			if (exists $ESCAPES{$c}) {
				$bytes .= sprintf '%x', ord($ESCAPES{$c});
			}
			else {
				$bytes .= sprintf '%x', int $c;
			}
			next;
		}
		
		$c = substr($$str_ref, 0, 1, '');
		if (substr($$str_ref, 0, 1) =~ /[a-f0-9]/) {
			$c .= substr($$str_ref, 0, 1, '');
		}
		$bytes .= $c;
	}
	
	hex($bytes);
}

sub load {
	my $self = shift;
	my $file = shift || $self->{'file'} || return;
	
	open my $fh, '<', $file or return;
	<$fh>; # omit header
	my $data = <$fh>;
	$data =~ s/\\"/"/g;
	close $fh;
	unless (substr($data, 0, length(MAGIC), '') eq MAGIC) {
		warn "$file does not seem to contain cookies";
		return;
	}
	
	my $cnt = _read_length_block(\$data);
	my ($len, $cookie, $cookie_str);
	for (my $i=0; $i<$cnt; $i++) {
		$len = _read_length_block(\$data);
		$cookie_str = substr($data, 0, $len, '');
		
		my @cookie_parts = split ';', $cookie_str;
		my ($domain, $path);
		for (my $i=1; $i<@cookie_parts; $i++) {
			last if $path && $domain;
			if (!$domain and ($domain) = $cookie_parts[$i] =~ /domain=(.+)/) {
				if (substr($domain, 0, 1) eq '.') {
					substr($domain, 0, 1) = '';
				}
				next;
			}
			if (!$path) {
				($path) = $cookie_parts[$i] =~ /path=(.+)/
			}
		}
		
		# generate fake request, so we can reuse extract_cookies() method
		my $req  = HTTP::Request->new(GET => "http://$domain$path");
		my $resp = HTTP::Response->new(200, 'OK', ['Set-Cookie', $cookie_str]);
		$resp->request($req);
		
		$self->extract_cookies($resp);
	}
	
	1;
}

sub as_string {

}

sub save {
	my $self = shift;
	my $file = shift || $self->{'file'} || return;
	open my $fh, '>', $file or die "Can't open $file: $!";
	print $fh "[General]\n";
	print $fh $self->as_string(!$self->{ignore_discard});
	close $fh;
	1;
}

1;
