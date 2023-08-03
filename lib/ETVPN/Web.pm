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

package ETVPN::Web v0.7.2;
use strict;
use warnings;


sub translate_port_share($) {
	my $env = shift;
	my $port_share_dir = $ENV{'ETVPN_OPENVPN_PORT_SHARE_DIR'} or return;
	my $remote_addr = $env->{'REMOTE_ADDR'} or return;
	my $remote_port = $env->{'REMOTE_PORT'} or return;
	my $tr_file = "$port_share_dir/[AF_INET]$remote_addr:$remote_port";
	unless (-f $tr_file) {
		$tr_file = "$port_share_dir/[AF_INET6]$remote_addr:$remote_port";
		unless (-f $tr_file) {
			$tr_file = "$port_share_dir/remote_addr:$remote_port";
			return unless -f $tr_file;
		}
	}

	open my $tr_h, '<', $tr_file or do {
		warn "WARNING: could not open $tr_file: $!\n";
		return;
	};
	my $tr_content = <$tr_h>;
	close $tr_h;
	unless ($tr_content) {
		warn "WARNING: $tr_file is empty\n";
		return;
	};
	chomp $tr_content;
	my ($addr, $port) = $tr_content =~ /^(?:\[AF_INET6?\])?(\S+):(\d+)$/;
	unless ($addr && $port) {
		warn "WARNING: ignoring invalid content from $tr_file\n";
		return;
	}
	$env->{'REMOTE_ADDR'} = $addr;
	$env->{'REMOTE_PORT'} = $port;
	my $req_uri = $env->{'REQUEST_URI'};
	print STDERR "request from OpenVPN proxied address $addr:$port as $remote_addr:$remote_port to ".($req_uri ? $req_uri : 'undefined request URI')."\n";
}


1;
