package HTTP::Cookies::PhantomJS;

use strict;
use HTTP::Cookies;
use HTTP::Headers::Util qw(_split_header_words join_header_words);
use HTTP::Date qw(str2time time2str);

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
	
	open my $fh, $file or return;
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
		
		for $cookie (_split_header_words($cookie_str)) {
			my($key, $val) = splice(@$cookie, 0, 2);
			my %hash;
			while (@$cookie) {
				my $k = shift @$cookie;
				my $v = shift @$cookie;
				$hash{$k} = $v;
			}
			my $version   = int delete $hash{version};
			my $path      = delete $hash{path};
			my $domain    = delete $hash{domain};
			my $port      = delete $hash{port};
			my $expires   = str2time(delete $hash{expires});
			
			my $path_spec = $path ? 1 : 0;
			my $secure    = 0;
			my $discard   = 0;
			
			my @array = ($version,$val,$port,
			             $path_spec,$secure,$expires,$discard);
			push(@array, \%hash) if %hash;
			$self->{COOKIES}{$domain}{$path}{$key} = \@array;
		}
	}
	
	1;
}

sub as_string {

}

sub save {

}

1;
