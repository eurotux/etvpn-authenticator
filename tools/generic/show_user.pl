#!/usr/bin/perl -w
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

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case);

use ETVPN::Cli;
use ETVPN::Conf;


#################################
### Globals
#################################
$|=1;
my $conf;
my $bconf;
my $username;
my $realm;
my $backend;
my $backend_username;
my $backend_password;

#### command line arguments
my $default_ini_file = '/etc/etvpn/etux-vpnserver.ini';
my $config_file = $default_ini_file;
my $need_help = 0;
my $objectname;


#######
# Subs and helpers
#######
sub help {
	print "Usage:\n";
	print "\t$0 [... options ...] username[\@realm]\n";
	print "\n";
	print "When needed, backend credentials will be prompted.\n";
	print "\n";
	print "Options:\n";
	print "\t-c|--config-file=FILE         Provide alternate configuration file. Default is $default_ini_file\n";
	print "\t-h|--help                     Show this help message.\n";
	print "\n";
	exit 1;
}

sub get_credentials() {
	if ($backend->need_admin_credentials()) {
		print "Need credentials for realm $realm\n";
		$backend_username = ETVPN::Cli::read_prompt("Enter backend username: ");
		$backend_password = ETVPN::Cli::read_prompt("Enter backend password: ", 1);
		$backend->connect_as($backend_username, $backend_password) or ETVPN::Cli::die_error($backend->get_error);
	}
}


###############
# Command Line
###############
my @cl_errors;
GetOptions (
	'h|help' => \$need_help,
	'c|config-file=s' => \$config_file,
) or push @cl_errors, "Invalid parameters.";
$objectname = shift @ARGV or  push @cl_errors, "Missing argument: username.";
if (@cl_errors) {
	print join("\n", @cl_errors)."\n\n";
	$need_help = 1;
}
help if $need_help;
$conf = ETVPN::Conf->new($config_file);


##############
# Perform actions
###############
my $backend_realm = $conf->get_username_backend_realm($objectname) or ETVPN::Cli::die_error("Unknown realm for user $objectname");
($backend, $username, $realm) = @$backend_realm;
$bconf = $backend->get_conf();

# Ask for credentials (if the realm needs admin credentials)
get_credentials();

my $login = $backend->get_user_login($username, $realm, 1) or ETVPN::Cli::die_error($backend->has_internal_error() ? $backend->get_error() : "user \"$username\" does not exist or does not match realm \"$realm\" current backend criteria");

my $ipv4_addr = $login->get_static_ip4();
my $ipv6_addr = ETVPN::Util::ipv6_from_prefix_ifid_tuple($login->get_static_ip6(), undef, undef);
$ipv6_addr = $ipv6_addr->short() if ref($ipv6_addr);
my $ip_routes = $login->get_full_push_routes_list();
my $push_routes = @$ip_routes ? [ sort map { $_->version() == 4 ? $_->prefix() : $_->short().'/'.$_->prefixlen() } @$ip_routes ] : '-';
if ($backend->has_internal_error()) {
	ETVPN::Cli::die_error($backend->get_error());
}

ETVPN::Cli::output_table([
	['Account name', $login->get_account_name()],
	['Realm', $realm],
	['Backend Type', $bconf->val('backend type')],
	['MFA enabled', $login->has_challenge_secret() ? 'Yes': 'No'],
	['Static IPv4 Address', defined($ipv4_addr) ? ($ipv4_addr->size() == 1 ? $ipv4_addr->ip() : 'from IP pool '.$ipv4_addr->print()) : '-'],
	['Static IPv6 Address', defined($ipv6_addr) ? $ipv6_addr : '-'],
	['Computed Push Routes', $push_routes],
], 4);
