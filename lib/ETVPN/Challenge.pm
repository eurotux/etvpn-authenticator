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

package ETVPN::Challenge 0.7.1;
use strict;
use warnings;
use ETVPN::Secret;
use ETVPN::Challenge::OTPAuth;
use ETVPN::Challenge::WebAuthn;


my %challenges = (
	'otpauth' => sub { return new ETVPN::Challenge::OTPAuth($_[0]); },
	'webauthn' => sub { return new ETVPN::Challenge::WebAuthn($_[0]); },
);


sub exists_challenge {
	my $name = shift;
	return defined($name) && exists($challenges{$name});
}


sub new_from_type {
	my ($conf, $type) = @_;

	if (exists_challenge($type)) {
		return &{$challenges{$type}}($conf);
	}

	return undef;
}


1;
