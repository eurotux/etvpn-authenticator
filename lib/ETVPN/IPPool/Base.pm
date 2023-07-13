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

package ETVPN::IPPool::Base v0.7.1;
use strict;
use warnings;
use parent qw(ETVPN::Actionable);


sub register_ovpn_instance {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->register_ovpn_instance($mgmt_address, $mgmt_port, $ovpn_pid)
	# it must call $self->set_registered() on success
	ETVPN::Logger::fatal('internal error: ippool base class register_ovpn_instance() called');
}


sub get_user_pool_ip {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->get_user_pool_ip($username, $pool, $realm, $ipver) and return a Net::IP object
	# it also must return an undef value if $self->is_registered() is not a true value
	ETVPN::Logger::fatal('internal error: ippool base class get_user_pool_ip() called');
}


sub free_user_address {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->free_user_address($username, $realm, $ipver) and return an integer with the amount of addresses freed, with -1 denoting error
	# it must check if $self->is_registered() is a true value and set an internal error (returning -1) if it isn't
	ETVPN::Logger::fatal('internal error: ippool base class free_user_address() called');
}


sub set_registered {
	my $self = shift;
	$self->{'registered'} = 1;
}


sub is_registered {
	my $self = shift;
	return $self->{'registered'};
}

1;
