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

package ETVPN::Backend v0.7.5;
use strict;
use warnings;


my %backends = (
	'ldap' => sub { use ETVPN::Backend::LDAP; return new ETVPN::Backend::LDAP(@_); },
	'sql' => sub { use ETVPN::Backend::SQL; return new ETVPN::Backend::SQL(@_); },
);


sub exists_backend {
	my $name = shift;
	return defined($name) && exists($backends{$name});
}


sub new_from_type {
	my ($conf, $type, $realm) = @_;

	if (exists_backend($type)) {
		return &{$backends{$type}}($conf, $realm);
	}

	return undef;
}


1;
