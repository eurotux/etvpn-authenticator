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

package ETVPN::Challenge::OTPAuth v0.7.2;
use strict;
use warnings;
use parent qw(ETVPN::Challenge::Base);

use ETVPN::Util;


my $prompt = 'Please enter authenticator code:';


sub is_pending {
	#my ($self, $login) = @_;
	return 1;
}


sub is_crv {
	my ($self, $login) = @_;

	# use CR protocol when the client doesn't support openurl IV_SSO capability
	return !$login->has_iv_sso_capability('crtext');
}


sub set_secret {
	my ($self, $login, $secret) = @_;

	# store secret for delayed validation
	$self->{'secret'} = $secret;
}


sub get_crv_prompt {
	my ($self, $login) = @_;

	return ($prompt, 1) if $self->is_crv($login);
	return (undef, 0);
}


sub _validate_totp_challenge {
	my ($self, $login, $secret, $user_challenge_reply) = @_;

	unless (defined($user_challenge_reply) && $user_challenge_reply ne '') {
		$self->add_error('invalid empty user otpauth response');
		return 0;
	}

	my $conf = $self->get_conf();

	# google auth and compatible
	my $hex_secret = join('', unpack '(H2)*', $secret);
	my %valid_codes;
	my @time_variants = ('');
	my $tolerance = $conf->val('otpauth tolerance');
	if ($tolerance > 0) {
		push @time_variants, ' -S '.quotemeta("-$tolerance sec");
		push @time_variants, ' -S '.quotemeta("+$tolerance sec");
	}
	foreach my $timeopt (@time_variants) {
		local $ENV{'LANG'} = 'C';
		my $oathcmd = quotemeta($conf->val('oathtool')).$timeopt.' --totp --digits '.quotemeta($conf->val('otpauth digits')).' '.quotemeta($hex_secret);
		my $otpcode = `$oathcmd`;
		if ($? == 0) {
			{ local $/ = "\n"; chomp $otpcode; }
			$valid_codes{$otpcode} = 1;
		}
		else {
			$self->add_internal_error('error executing oathtool');
			return 0;
		}
	}
	if (exists($valid_codes{$user_challenge_reply})) {
		ETVPN::Logger::log('otpauth verification successful');
		return 1;
	}
	$self->add_error('otpauth verification failed');
	return 0;
}


sub validate {
	my ($self, $login, $secret, $user_challenge_reply) = @_;

	if ($self->is_crv($login)) {
		# CR challenge phase 2 (client reconnected and user pressed enter on prompt)
		return $self->_validate_totp_challenge($login, $secret, $user_challenge_reply);
	}
	else {
		# Pending challenge phase 1
		$self->set_secret($login, $secret);
	}
	# Pending challenge phase 2 is only handled in validate_pending_auth
	return 0;
}


sub validate_pending_auth {
	my ($self, $login, $user_challenge_reply) = @_;

	return $self->_validate_totp_challenge($login, $self->{'secret'}, $user_challenge_reply);
}


sub get_pending_string {
	#my ($self, $login) = @_;
	return 'CR_TEXT:R,E:'.ETVPN::Util::ovpn_mgmt_escape($prompt);
}


1;
