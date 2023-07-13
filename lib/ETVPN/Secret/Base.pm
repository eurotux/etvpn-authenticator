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

package ETVPN::Secret::Base 0.7.1;
use strict;
use warnings;
use parent qw(ETVPN::Actionable);

use ETVPN::Login;


# TODO: add possibility to lock account based on secret data


sub decode {
	# parent class, not supposed to be executed
	# overriden method should accept a ETVPN::Login object as argument and return a array ref with challenge type and data,
	# or undef on failure
	# user's unique id can be undef on the passed ETVPN::Login, its validation should be made on the ETVPN::Backend methods
	ETVPN::Logger::fatal('secret base class decode called');
}


sub encode {
	# parent class, not supposed to be executed
	# overriden method should accept a challenge type, user's unique id and plain secret data as arguments and return the encrypted string
	ETVPN::Logger::fatal('internal error: secret base class encode called');
}


1;
