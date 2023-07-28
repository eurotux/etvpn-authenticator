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

package ETVPN::Login v0.7.1;
use strict;
use warnings;

use ETVPN::Util;


sub new {
	my ($class, @params) = @_;

	# structure format: [ \%params, \@messages ]
	my $self = bless [ { @params }, [] ], $class;

	# account name value is always mandatory
	die "Internal error: account name parameter not specified\n" unless defined($self->get_account_name());

	return $self;
}


sub is_success {
	my $self = shift;
	return $self->[0]->{'success'};
}


sub set_success {
	my ($self, $success) = @_;
	$self->[0]->{'success'} = $success;
}


sub get_account_name {
	my $self = shift;
	return $self->[0]->{'account name'};
}


sub get_unique_id {
	my $self = shift;
	return $self->[0]->{'unique id'};
}


sub set_realm {
	my ($self, $realm) = @_;
	$self->[0]->{'realm'} = $realm;
}


sub get_realm {
	my $self = shift;
	return $self->[0]->{'realm'};
}


sub set_cid_kid {
	my ($self, $cid, $kid) = @_;
	$self->[0]->{'cid kid'} = [$cid, $kid];
}


sub get_cid_kid {
	my ($self) = @_;
	return $self->[0]->{'cid kid'};
}


sub set_auth_data {
	my ($self, $user_login, $auth_sid) = @_;
	$self->[0]->{'auth data'} = [$user_login, $auth_sid];
}


sub get_auth_data {
	my $self = shift;
	my $auth_data = $self->[0]->{'auth data'};
	return defined($auth_data) ? @{$self->[0]->{'auth data'}} : (undef, undef);
}


sub set_env {
	my ($self, $env) = @_;
	$self->[0]->{'env'} = $env;
}


sub get_env {
	my ($self) = @_;
	return $self->[0]->{'env'};
}


sub has_env {
	my ($self, $key) = @_;
	return exists($self->[0]->{'env'}->{'key'});
}


sub has_iv_sso_capability {
	my ($self, $capability) = @_;

	my $iv_sso_cap = $self->[0]->{'iv_sso_cap'};
	if (!defined($iv_sso_cap)) {
		my $iv_sso = $self->get_env()->{'IV_SSO'};
		if (defined($iv_sso)) {
			$iv_sso_cap = $self->[0]->{'iv_sso_cap'} = { map { $_ => 1; } split(/,/, $iv_sso) };
		}
		else {
			return 0;
		}
	}

	return exists($iv_sso_cap->{$capability});
}


sub is_pending_auth {
	my $self = shift;
	my $chlg = $self->get_associated_challenge();
	return (defined($chlg) && $chlg->is_pending($self));
}


sub set_associated_challenge {
	my ($self, $challenge) = @_;
	$self->[0]->{'associated challenge'} = $challenge;
}


sub get_associated_challenge {
	my $self = shift;
	return $self->[0]->{'associated challenge'};
}


sub get_challenge_secret {
	my $self = shift;
	return $self->[0]->{'secret'};
}


sub has_challenge_secret {
	my $self = shift;
	return defined($self->[0]->{'secret'}) && $self->[0]->{'secret'} ne '';
}


sub set_static_ip4 {
	my ($self, $addr) = @_;
	$self->[0]->{'static ip4'} = $addr;
}


sub get_static_ip4 {
	my $self = shift;
	return $self->[0]->{'static ip4'};
}


sub set_static_ip6 {
	my ($self, $addr) = @_;
	$self->[0]->{'static ip6'} = $addr;
}


sub get_static_ip6 {
	my $self = shift;
	return $self->[0]->{'static ip6'};
}


sub set_push_routes {
	my ($self, $routes) = @_;
	$self->[0]->{'push routes'} = $routes;
}


sub get_push_routes {
	my $self = shift;
	my $routes = $self->[0]->{'push routes'};
	return defined($routes) ? $routes : {};
}


sub set_push_routes_ip4 {
	my ($self, $routes) = @_;
	$self->[0]->{'push routes ip4'} = $routes;
}


sub get_push_routes_ip4 {
	my $self = shift;
	my $routes = $self->[0]->{'push routes ip4'};
	return defined($routes) ? $routes : {};
}


sub set_push_routes_ip6 {
	my ($self, $routes) = @_;
	$self->[0]->{'push routes ip6'} = $routes;
}


sub get_push_routes_ip6 {
	my $self = shift;
	my $routes = $self->[0]->{'push routes ip6'};
	return defined($routes) ? $routes : {};
}


sub get_full_push_routes_list {
	my $self = shift;
	return ETVPN::Util::hashes_values($self->get_push_routes(), $self->get_push_routes_ip4(), $self->get_push_routes_ip6());
}


1;
