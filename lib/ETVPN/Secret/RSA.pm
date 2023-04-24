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

package ETVPN::Secret::RSA 0.7;
use strict;
use warnings;
use parent qw(ETVPN::Secret::Base);

use File::stat;
use MIME::Base64;
use Crypt::OpenSSL::RSA;
use Bytes::Random::Secure;
use Storable qw(nfreeze thaw);
use ETVPN::Login;

sub decode {
	my ($self, $login) = @_;

	my $conf = $self->get_conf();

	# validate data according to signature and decrypt it
	my $safe_data = $login->get_challenge_secret() or do {
		# should have been already validated so marked as internal error if this is reached
		$self->add_internal_error("login has no challenge secret defined");
		return undef;
	};
	my $safe_secret;
	my ($b64_safe_secret, $b64_safe_signature) = split(/:/, $safe_data, 2);
	unless ( defined($b64_safe_secret) && defined($b64_safe_signature) &&
		 defined( $safe_secret = decode_base64($b64_safe_secret)) ) {
		$self->add_error("failure decoding stored secret: invalid format");
		return undef;
	};
	my $signature = decode_base64($b64_safe_signature) or do {
		$self->add_error("failure decoding stored secret signature");
		return undef;
	};
	my $rsa_priv = $self->_read_rsa_key() or return undef;
	my $serialized = eval { $rsa_priv->decrypt($safe_secret) };
	if ($@) {
		$self->add_error("could not decrypt stored user secret: $@");
		return undef;
	}
	unless ($rsa_priv->verify($serialized, $signature)) {
		$self->add_error("stored user secret failed signature validation");
		return undef;
	}

	# deserialize [$type, $data] (ignore salt)
	my ($salt, $type, $unique_id, $data) = eval { @{thaw($serialized)}; };
	if ($@) {
		$self->add_error("failure deserializing stored secret: $@");
		return undef;
	}
	unless (defined($type) && defined($data)) {
		$self->add_error("stored user secret has missing deserialized type or data");
		return undef;
	}

	my $intended_unique_id = $login->get_unique_id();
	do {
		no locale;
		if (defined($intended_unique_id) && (!defined($unique_id) || ($unique_id cmp $intended_unique_id) != 0)) {
			$self->add_error("stored user secret unique id does not correspond to user's unique_id");
			return undef;
		}
	};

	return [$type, $data];
}


sub encode {
	my ($self, $type, $unique_id, $data) = @_;

	my $rsa_priv = $self->_read_rsa_key() or return undef;

	# serialize [$type, $data] along with some salt and encrypt them
	my $serialized = nfreeze([random_bytes(16), $type, $unique_id, $data]);
	my $encrypted;
	my $signature;
	eval {
		$encrypted = $rsa_priv->encrypt($serialized);
		$signature = $rsa_priv->sign($serialized);
	};
	my $error = $@;
	chomp($error) if $error;
	if ($error || !defined($encrypted) || !defined($signature)) {
		$self->add_internal_error("error encrypting and signing - please confirm RSA key options in configuration" . ($error ? ": $error" : ""));
		return undef;
	}
	my $safe_data = encode_base64($encrypted).':'.encode_base64($signature);
	$safe_data =~ s/[\r\n]//g;

	return $safe_data;
}


sub _read_rsa_key {
	my $self = shift;

	my $ssl_key_file = $self->get_conf()->val('ssl key');

	my $st = stat($ssl_key_file) or do {
		$self->add_internal_error("can't stat ssl key file $ssl_key_file: $!");
		return undef;
	};
	if ($st->mode & 0037) {
		$self->add_internal_error("refusing to use ssl key file with insecure or inadequate permissions - group can (at most) be readable and no world permissions can be set - KEY FILE MAY HAVE BEEN COMPROMISED!");
		return undef;
	}

	open my $rsa_priv_fh, '<', $ssl_key_file or do {
		$self->add_internal_error("error opening $ssl_key_file: $!");
		return undef;
	};

	my $rsa_priv = eval { Crypt::OpenSSL::RSA->new_private_key(join('', <$rsa_priv_fh>)) };
	if ($@) {
		$rsa_priv = undef;
		$self->add_internal_error("invalid RSA private key: $@");
	}
	close $rsa_priv_fh;

	return $rsa_priv;
}


1;
