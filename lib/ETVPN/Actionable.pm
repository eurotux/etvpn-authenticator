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

package ETVPN::Actionable v0.7.4;
use strict;
use warnings;

use ETVPN::Logger;
use ETVPN::Conf;


sub new {
	my ($class, $conf) = @_;

	ETVPN::Logger::fatal("Internal error: undefined conf while initializing $class backend") unless defined($conf);

	return bless {
		'conf' => $conf,
		'error' => [],
		'has_internal_error' => 0,
	}, $class;
}


sub get_conf {
	my $self = shift;
	return $self->{'conf'};
}


sub get_errors {
	my ($self, $keep) = @_;
	my $errors = $self->{'error'};
	$self->clear_error() unless $keep;
	return @{$errors};
}


sub get_error {
	my ($self, $keep) = @_;
	return join('; ', $self->get_errors($keep));
}


sub add_error {
	my ($self, $error) = @_;
	push @{$self->{'error'}}, $error;
}


sub has_error {
	my $self = shift;
	return (scalar(@{$self->{'error'}}) > 0);
}


sub add_internal_error {
	my ($self, $error) = @_;
	$self->{'has_internal_error'} = 1;
	$self->add_error($error);
}


sub has_internal_error {
	my $self = shift;
	return $self->{'has_internal_error'};
}


sub clear_error {
	my $self = shift;
	$self->{'error'} = [];
	$self->{'has_internal_error'} = 0;
}


1;
