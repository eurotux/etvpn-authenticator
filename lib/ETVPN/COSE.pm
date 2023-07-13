# ETVPN Authenticator for OpenVPN servers
# Copyright (C) 2023 Eurotux Informática S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package ETVPN::COSE v0.7.1;
use warnings;
use strict;

use MIME::Base64 qw(decode_base64url);
use CBOR::XS;


# https://datatracker.ietf.org/doc/html/rfc8152#section-13
my %ktys = (
	# TODO: list is not complete, but at the moment we only use EC2
	'1' => 'Octet Key Pair (OKP)',
	'2' => 'Elliptic Curve Keys w/ x- and y-coordinate pair (EC2)',
	'3' => 'Symmetric Keys',
);

# https://datatracker.ietf.org/doc/html/rfc8152#section-8
my %algs = (
	# TODO: list is not complete, but at the moment we only use -7 when registering
	'-7' => 'ECDSA w/ SHA-256',
	'-35' => 'ECDSA w/ SHA-384',
	'-36' => 'ECDSA w/ SHA-512',
);


sub _val_from ($$) {
	my ($h, $k) = @_;
	return "Not defined" unless defined($k);
	my $v = $h->{$k};
	return defined($v) ? $v : 'Unknown';
}


sub base64url_pubkey_details($) {
	my $k = shift;

	my $cbor_key = decode_base64url($k) or do {
		warn "Problem decoding key: not in valid base64url format\n";
		return undef;
	};
	my $dk = eval { decode_cbor($cbor_key) };
	if ($@) {
		warn "Problem decoding key: $@\n";
	}
	if ($@ || !defined($dk)) {
		return undef;
	}

	# https://datatracker.ietf.org/doc/html/rfc8152#section-16.5
	my $kty = $dk->{'1'};
	my $alg = $dk->{'3'};

	# keep order, return as list
	return [
		['Key Type' => _val_from(\%ktys, $kty)],
		['Key Algorithm' => _val_from(\%algs, $alg)],
	];
}
