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

package ETVPN::Session v0.7.3;
use strict;
use warnings;
use Bytes::Random::Secure qw(random_bytes);


my $sess_dsn = 'driver:file;serializer:default;id:static';


sub dsn() {
	return $sess_dsn;
}


sub safe_session_name($) {
	my ($sess_opts) = @_;
	my $tmpsess;
	my $nsid;
	do {
		$nsid = join('', unpack '(H2)*', random_bytes(24));
	} while ( ($tmpsess = CGI::Session->load($sess_dsn, $nsid, $sess_opts)) && !$tmpsess->is_empty );
	return $nsid;
}


1;
