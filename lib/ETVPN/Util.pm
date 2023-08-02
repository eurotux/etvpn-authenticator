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

package ETVPN::Util v0.7.1;
use strict;
use warnings;

use Net::IP qw(:PROC);
use Bytes::Random::Secure qw(random_string_from);

use ETVPN::Logger;


sub ovpn_mgmt_escape($) {
	my $s = shift;
	$s =~ s/([\s"\\])/\\$1/g;
	return $s;
}


sub internal_error_text($) {
	my $internal_error = shift;
	my @errors;
	foreach my $error (sort keys %$internal_error) {
		push @errors, "$error ERROR" if $internal_error->{$error};
	}
	return @errors ? join(', ', @errors) : 'ALL_OK';
}


sub add_new_routes($$) {
	my ($existing, $new_routes) = @_;
	$existing = {} unless defined $existing;
	# Work with hashes like ip_short/prefix => ip_object to help avoid duplicates
	foreach my $addr (@$new_routes) {
		my $ip = new Net::IP($addr);
		ETVPN::Logger::fatal_code(99, "invalid network address: $addr") if !$ip || !$ip->prefixlen();
		my $ipkey = $ip->version() == 4 ? $ip->prefix() : $ip->short().'/'.$ip->prefixlen();
		next if exists($existing->{$ipkey});
		$existing->{$ipkey} = $ip;
	}
	return $existing;
}


sub add_new_ip_objects($$) {
	my ($existing, $new_objs) = @_;
	$existing = {} unless defined $existing;
	# Also work with hashes like ip_short/prefix => ip_object to help avoid duplicates
	# but here the input consists of already valid Net::IP objects, and this sub does not die, so it's suitable to be called
	# where exiting is not desirable
	foreach my $ip (@$new_objs) {
		my $ipkey = $ip->version() == 4 ? $ip->prefix() : $ip->short().'/'.$ip->prefixlen();
		next if exists($existing->{$ipkey});
		$existing->{$ipkey} = $ip;
	}
	return $existing;
}


sub hashes_values(@) {
	my %all;
	foreach my $h (@_) {
		%all = (%all, %$h);
	}
	return [values(%all)];
}


sub net_peer_ip($$;$) {
	my ($addr, $mask, $ipver) = @_;
	$ipver = 4 unless defined($ipver);
	my $addrbin = ip_iptobin($addr, $ipver);
	unless (defined($addrbin)) {
		ETVPN::Logger::log("WARNING: peer IP requested for invalid IPv$ipver address $addr");
		return undef;
	}
	my $maskbin = ip_iptobin($mask, $ipver);
	unless (defined($maskbin)) {
		ETVPN::Logger::log("WARNING: invalid netmask $mask while computing peer IP for IPv$ipver address $addr");
		return undef;
	}
	my $netbin = $addrbin & $maskbin;
	my $add = scalar('0' x ($ipver == 4 ? 31 : 127).'1');
	my $peerip = new Net::IP(ip_bintoip(ip_binadd($netbin, $add), $ipver), $ipver) or return undef;
	unless (defined($peerip)) {
		ETVPN::Logger::log("WARNING: error computing peer IP for IPv$ipver address $addr");
		return undef;
	}
	if ($peerip->ip() eq $addr) {
		$add = scalar('0' x ($ipver == 4 ? 30 : 126).'10');
		$peerip = new Net::IP(ip_bintoip(ip_binadd($netbin, $add), $ipver), $ipver) or return undef;
	}
	return $peerip->ip();
}


sub ipv6_from_prefix_ifid_tuple($$$) {
	my ($static_ip6, $ip6_local, $ifconfig_ipv6_netbits) = @_;
	return undef unless defined($static_ip6);
	my $ip;
	my ($pref, $int_id) = @$static_ip6;
	if (defined($int_id)) {
		my $pref_bin;
		if (defined($pref)) {
			$pref_bin = $pref->binip();
		}
		elsif (defined($ip6_local)) {
			# called by the auth daemon
			# only interface ID given, derive prefix from OpenVPN server's IPv6 address
			my $mask = scalar('1' x $ifconfig_ipv6_netbits) . scalar('0' x (128-$ifconfig_ipv6_netbits));
			$pref_bin = $ip6_local->binip() & $mask;
		}
		else {
			# show_user.pl tool only
			return 'Interface ID '.$int_id->short();
		}
		$ip = new Net::IP(ip_bintoip($pref_bin | $int_id->binip(), 6), 6) or do {
			ETVPN::Logger::log('WARNING: could not derive a valid static IPv6 address from user data returned by backend');
			return undef;
		};
	}
	else {
		$ip = $pref;
	}
	return $ip;
}


sub is_strong_password($) {
	my $p = shift;
	return $p =~ /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/
}


sub strong_crypt($) {
	my $p = shift;
	crypt($p, '$6$'.random_string_from(join('', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')), 16));
}


1;
