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
use DBI;
use List::MoreUtils qw(each_array);

use ETVPN::Cli;
use ETVPN::Conf;


#################################
### Globals
#################################
$|=1;
my $conf;
my $bconf;
my $listpattern;
my $username;
my $realm;
my $backend;
my $dbh;
my $admin_username;
my $admin_password;

#### command line arguments
my $default_ini_file = '/etc/etvpn/etux-vpnserver.ini';
my $config_file = $default_ini_file;
my $command;
my $objectname;
my $newname;
my $groupname;
my $list_routes = 0;
my $list_subgroups = 0;
my $list_users = 0;
my @add_to_groups;
my @remove_from_groups;
my $no_groups = 0;
my $ipv4_address;
my $no_ipv4_address = 0;
my $ipv6_address;
my $no_ipv6_address = 0;
my @add_ipv4_routes;
my @remove_ipv4_routes;
my $no_ipv4_routes = 0;
my @add_ipv6_routes;
my @remove_ipv6_routes;
my $no_ipv6_routes = 0;
my $dry_run = 0;
my $need_help = 0;


#######
# Subs and helpers
#######
sub help {
	print "Usage:\n";
	print "\t$0 [... options ...] <command> ...\n";
	print "\n";
	print "Commands:\n";
	print "\tuserlist [username_sql_like_pattern][\@realm]\n";
	print "\t\tList users and (when existing) respective static IP addresses\n";
	print "\t\tUnless the default backend is of SQL type, you must specify it\n";
	print "\t\tExamples:$0\n";
	print "\t\t\t$0 userlist\n";
	print "\t\t\t$0 userlist acme_%\n";
	print "\t\t\t$0 userlist \@non_default_realm\n";
	print "\t\t\t$0 userlist %mypattern%\@non_default_realm\n";
	print "\tusershow username[\@realm]\n";
	print "\t\tShow user details, including (when existing) static IP addresses, routes and group memberships\n";
	print "\tuseradd username[\@realm]\n";
	print "\t\tAdd a new user (see options below)\n";
	print "\tuserdel username[\@realm]\n";
	print "\t\tDelete an existing user\n";
	print "\tusermod username[\@realm]\n";
	print "\t\tModify user's attributes (see options below) and group memberships\n";
	print "\t\tFor changing the password, use the 'passwd' command\n";
	print "\tpasswd username[\@realm]\n";
	print "\t\tModify a user's password\n";
	print "\tlock username[\@realm]\n";
	print "\t\tLock a user account\n";
	print "\t\tThis puts a '!' in front of the encrypted password, effectively disabling the password.\n";
	print "\tunlock username[\@realm]\n";
	print "\t\tUnlock a user account\n";
	print "\tgrouplist [groupname_sql_like_pattern][\@realm]\n";
	print "\t\tList groups and (when existing) respective static IP addresses\n";
	print "\t\tUnless the default backend is of SQL type, you must specify it\n";
	print "\tgroupshow groupname[\@realm]\n";
	print "\t\tShow group details, including (when existing) routes and members\n";
	print "\tgroupadd groupname[\@realm]\n";
	print "\t\tAdd a new group (see options below)\n";
	print "\tgroupdel groupname[\@realm]\n";
	print "\t\tDelete an existing group\n";
	print "\tgroupmod groupname[\@realm]\n";
	print "\t\tModify group's attributes (see options below)\n";
	print "\tgrouprename groupname[\@realm] newname\n";
	print "\t\tRename a group (beware of options referencing group names in your configuration if you do this)\n";
	print "\n";
	print "When needed, some of the above commands will prompt for admin backend credentials.\n";
	print "\n";
	print "Options:\n";
	print "\t-c|--config-file=FILE           Provide alternate configuration file.\n";
	print "\t                                Default is $default_ini_file\n";
	print "\t-h|--help                       Show this help message.\n";
	print "\n";
	print "Options for grouplist:\n";
	print "\t--routes                        Also show each group's routes when listing\n";
	print "\t--subgroups                     Also show each group's subgroups when listing\n";
	print "\t--users                         Also show each group's user members when listing\n";
	print "\n";
	print "Options for useradd, usermod, groupadd and groupmod commands:\n";
	print "\t--ipv4-address=ipv4_address     Set a user's IPv4 static address (useradd and usermod only)\n";
	print "\t--no-ipv4-address               Unset a user's IPv4 static address (useradd and usermod only)\n";
	print "\t--ipv6-address=ipv6_address     Set a user's IPv6 static address (useradd and usermod only)\n";
	print "\t--no-ipv6-address               Unset a user's IPv6 static address (useradd and usermod only)\n";
	print "\t--add-ipv4-route=ipv4_route     Add a user or group IPv4 static route\n";
	print "\t                                To add multiple routes at once, repeat this option multiple times\n";
	print "\t--remove-ipv4-route=ipv4_route  Remove a user or group IPv4 static route\n";
	print "\t                                To remove multiple routes at once, repeat this option multiple times\n";
	print "\t--no-ipv4-routes                Unset any user or group IPv4 static routes\n";
	print "\t--add-ipv6-route=ipv6_route     Add a user or group IPv6 static route\n";
	print "\t                                To add multiple routes, repeat this option multiple times\n";
	print "\t--remove-ipv6-route=ipv6_route  Remove a user or group IPv6 static route\n";
	print "\t                                To remove multiple routes, repeat this option multiple times\n";
	print "\t--no-ipv6-routes                Unset any user or group IPv6 static routes\n";
	print "\t--add-to-group=group               Add user/group to a group\n";
	print "\t                                To set in multiple groups at once, repeat this option multiple times\n";
	print "\t--remove-from-group=group            Remove user/group from a group\n";
	print "\t                                To remove from multiple groups at once, repeat this option multiple\n";
	print "\t                                times\n";
	print "\t--no-groups                     Remove user/group from any group\n";
	print "\t                                Cannot be used at the same time as --add-to-group\n";
	print "\n";
	exit 1;
}

sub get_backend_realm($) {
	my $rlm_name = shift;
	$backend = $conf->get_backend($rlm_name) or do {
		if (defined($rlm_name)) {
			ETVPN::Cli::die_error("Unknown realm \"$rlm_name\"");
		}
		else {
			ETVPN::Cli::die_error("No realm specified and no default realm configured");
		}
	};
	$realm = $backend->get_realm() unless defined($realm);
}

sub get_credentials() {
	if ($backend->need_admin_credentials()) {
		print "Need credentials for realm $realm\n";
		$admin_username = ETVPN::Cli::read_prompt("Enter admin backend username: ");
		$admin_password = ETVPN::Cli::read_prompt("Enter admin backend password: ", 1);
		$backend->connect_as($admin_username, $admin_password) or ETVPN::Cli::die_error($backend->get_error);
	}
}

sub ask_crypt_newpassword() {
	my $password;
	while (1) {
		$password = ETVPN::Cli::read_prompt("Enter new user's password: ", 1);
		last if ETVPN::Util::is_strong_password($password);
		ETVPN::Cli::issue_warn("Password is too weak");
	}
	my $verify = ETVPN::Cli::read_prompt("Verify new user's password: ", 1);
	ETVPN::Cli::die_error("Passwords do not match") if $password ne $verify;

	return ETVPN::Util::strong_crypt($password);
}

sub user_dbid() {
	# will exit with error if user does not exist or is a duplicate
	my $row = $backend->userdata_from_db($username, $realm, 'id');
	ETVPN::Cli::die_error($backend->get_error) unless $backend->check_row($row, 'id');
	return $row->{'id'};
}

sub group_dbid() {
	# will exit with error if group does not exist or is a duplicate
	my $row = $backend->groupdata_from_db($groupname, 'id');
	ETVPN::Cli::die_error($backend->get_error) unless $backend->check_row($row, 'id');
	return $row->{'id'};
}

sub validate_new_name($) {
	my $name = shift;
	ETVPN::Cli::die_error('Invalid name - must start with with a letter or a number, followed by at least one more valid character which can be a letter, a number, an underscore or a dash (minus sign)') unless $name =~ /^[A-Za-z0-9][A-Za-z0-9_\.-]+$/;
}

sub validate_ip($$$;$$) {
	my ($addr, $version, $want_prefix, $possible_db_error, $non_fatal) = @_;

	my $ip = new Net::IP($addr, $version);
	unless ($ip && $ip->prefixlen()) {
		return undef if $non_fatal;
		ETVPN::Cli::die_error("Invalid IPv$version address: $addr".($possible_db_error ? " - YOUR DATABASE HAS A CORRUPTED IPv$version VALUE, PLEASE FIX IT (--no-ipv$version-address or --no-ipv$version-routes may help, or contact your database administrator if you're using a custom database)" : ''));
	}
	my $ret = $version == 4 ? $ip->ip() : $ip->short();
	$ret .= '/'.$ip->prefixlen() if $want_prefix;
	return $ret;
}

sub check_existing_user_ip($$$$) {
	my ($addr_value, $table, $addr_column, $db_id_except) = @_;

	my $query = 'SELECT '.$bconf->val('users col name').' FROM '.$bconf->val('users table')." WHERE $addr_column = ?";
	my @params = ( $addr_value );
	if (defined($db_id_except)) {
		$query .= ' AND '.$bconf->val('users col id').' != ?';
		push @params, $db_id_except;
	}
	my $sth = $dbh->prepare($query) or ETVPN::Cli::die_error('Database query preparation failed: '.$DBI::errstr);
	$sth->execute(@params) or ETVPN::Cli::die_error('Database query execution failed: '.$DBI::errstr);
	my @existing;
	while (my $row = $sth->fetchrow_arrayref()) {
		push @existing, $row->[0];
	}
	ETVPN::Cli::die_error("User IP address $addr_value is already defined for: ".join(', ', @existing)) if @existing;
}

sub ip_version_value($$$$$$$;$) {
	my ($table, $cols, $values, $version, $type, $set_opt, $unset_opt, $db_id) = @_;

	my $is_opt_arr = (ref($set_opt) eq 'ARRAY');
	my $is_opt_set = (defined($set_opt) && (!$is_opt_arr || @$set_opt));

	# nothing to do here unless one of the set or unset value options are set
	return unless $is_opt_set || $unset_opt;

	my $col_name = $bconf->val("$table col ipv$version $type") or ETVPN::Cli::die_error("Can't change or set $table ipv$version $type unless \"$table col ipv$version $type\" option is set for the SQL realm \"$realm\" backend");
	push @$cols, $col_name;

	if ($is_opt_set)  {
		ETVPN::Cli::die_error("Conflicting options: --no-ipv$version-$type and --ipv$version-$type") if $unset_opt;
		if ($is_opt_arr) {
			push @$values, join(' ', @$set_opt);
		}
		else {
			push @$values, validate_ip($set_opt, $version, 0);
		}
		if (!$bconf->val('users allow same fixed ip address') && $type eq 'address') {
			check_existing_user_ip($set_opt, $table, $col_name, $db_id);
		}
	}
	else {
		# the unset option is true
		push @$values, undef;
	}
}

sub filter_routes($$$$$) {
	my ($version, $existing, $add, $remove, $want_unset) = @_;
	return ([], 1) if $want_unset;
	my %routes = map { $_ => 1 } (
		( map { validate_ip($_, $version, 1, 1) } @$existing ),
		( map { validate_ip($_, $version, 1) } @$add )
	);
	my $spref = $version == 4 ? '32' : '128';
	foreach my $rr (@$remove) {
		my $vr = validate_ip($rr, $version, 1, 0, 1);
		delete $routes{$vr} if defined($vr);
		delete $routes{$rr} if !defined($vr) || $rr ne $vr;
	}
	my $routelist = [ sort keys %routes ];
	return ($routelist, @$existing ? @$routelist == 0 : 0);
}

sub fill_ip_options($$$$) {
	my ($db_id, $table, $cols, $values) = @_;

	# address (user only)
	if ($table eq 'users') {
		ip_version_value($table, $cols, $values, 4, 'address', $ipv4_address, $no_ipv4_address, $db_id);
		ip_version_value($table, $cols, $values, 6, 'address', $ipv6_address, $no_ipv6_address, $db_id);
	}

	# routes
	ETVPN::Cli::die_error("Conflicting options: --no-ipv4-routes and --add-ipv4-route") if $no_ipv4_routes && @add_ipv4_routes;
	ETVPN::Cli::die_error("Conflicting options: --no-ipv6-routes and --add-ipv6-route") if $no_ipv6_routes && @add_ipv6_routes;
	my $existing_ipv4 = [];
	my $existing_ipv6 = [];
	if ($db_id) {
		my @cols;
		my $col4_name;
		my $col6_name;
		if (!$no_ipv4_routes && (@add_ipv4_routes || @remove_ipv4_routes)) {
			$col4_name = $bconf->val("$table col ipv4 routes") or ETVPN::Cli::die_error("Can't change or set $table ipv4 routes unless \"$table col ipv4 routes\" option is set for the SQL realm \"$realm\" backend");
			push @cols, $col4_name;
		}
		if (!$no_ipv6_routes && (@add_ipv6_routes || @remove_ipv6_routes)) {
			$col6_name = $bconf->val("$table col ipv6 routes") or ETVPN::Cli::die_error("Can't change or set $table ipv6 routes unless \"$table col ipv6 routes\" option is set for the SQL realm \"$realm\" backend");
			push @cols, $col6_name;
		}
		if (@cols) {
			my $query = 'SELECT '.join(',', @cols).' FROM '.$bconf->val("$table table").' WHERE '.$bconf->val("$table col id").'=?';
			my $sth = $dbh->prepare($query) or ETVPN::Cli::die_error('Database query preparation failed: '.$DBI::errstr);
			$sth->execute($db_id) or ETVPN::Cli::die_error('Database query execution failed: '.$DBI::errstr);
			my $row = $sth->fetchrow_hashref() or ETVPN::Cli::die_error("Inconsistency error getting current $table routes information, please check your database integrity");
			if ($col4_name) {
				my $rv = $row->{$col4_name};
				$existing_ipv4 = [ split(/\s*[\s,]\s*/, $rv) ] if defined($rv);
			}
			if ($col6_name) {
				my $rv = $row->{$col6_name};
				$existing_ipv6 = [ split(/\s*[\s,]\s*/, $rv) ] if defined($rv);
			}
		}
	}
	my ($ipv4_routes, $unset_ipv4_routes) = filter_routes(4, $existing_ipv4, \@add_ipv4_routes, \@remove_ipv4_routes, $no_ipv4_routes);
	ip_version_value($table, $cols, $values, 4, 'routes', $ipv4_routes, $unset_ipv4_routes);
	my ($ipv6_routes, $unset_ipv6_routes) = filter_routes(6, $existing_ipv6, \@add_ipv6_routes, \@remove_ipv6_routes, $no_ipv6_routes);
	ip_version_value($table, $cols, $values, 6, 'routes', $ipv6_routes, $unset_ipv6_routes);
}

sub check_groups() {
	my %rg = map { $_ => 1 } @add_to_groups,@remove_from_groups;
	if (keys(%rg) != @add_to_groups+@remove_from_groups)  {
		ETVPN::Cli::die_error("Group(s) specified in --add-to-group can't be specified in --remove-from-group at the same time");
	}
	my $group_union = join(' UNION ', map { 'SELECT '.$dbh->quote($_).' AS name' } @add_to_groups,@remove_from_groups);
	my $invalid_groups = $dbh->selectcol_arrayref("SELECT wanted.name FROM ($group_union) AS wanted LEFT JOIN ".$bconf->val('groups table').' AS g ON g.'.$bconf->val('groups col name').'=wanted.name WHERE g.name IS NULL') or ETVPN::Cli::die_error('Database group validity query failed: '.$DBI::errstr);
	ETVPN::Cli::die_error('Non existing group'.(@$invalid_groups == 1 ? '' : 's').': '.join(', ', @$invalid_groups)) if @$invalid_groups;
	return 1;
}

sub set_user_groups($) {
	return 0 unless $no_groups || @add_to_groups || @remove_from_groups;
	ETVPN::Cli::die_error("SQL realm \"$realm\" does not have a defined \"groups table\" therefore group management can't be performed for this realm") unless $bconf->isdef('groups table');
	ETVPN::Cli::die_error("Conflicting options: --no-groups and --add-to-group") if $no_groups && @add_to_groups;
	my $q_uid = $dbh->quote(shift);
	my $ug_rel = $bconf->val('users groups relation table');
	my $ug_uid = $bconf->val('users groups user id');
	if ($no_groups) {
		my $mod = $dbh->do("DELETE FROM $ug_rel WHERE $ug_uid=$q_uid") or ETVPN::Cli::die_error('database error clearing user/group membership: '.$DBI::errstr);
		return $mod ne '0E0';
	}
	return 0 unless check_groups();
	my $ug_gid = $bconf->val('users groups group id');
	my $g_table = $bconf->val('groups table');
	my $g_id = $bconf->val('groups col id');
	my $g_name = $bconf->val('groups col name');
	my $changed = 0;
	if (@add_to_groups) {
		# add to group(s)
		my $q_add_to_groups = join(',', map { $dbh->quote($_) } @add_to_groups);
		my $mod = $dbh->do("INSERT INTO $ug_rel ($ug_uid,$ug_gid) SELECT $q_uid,$g_id FROM $g_table WHERE $g_name IN ($q_add_to_groups) AND $g_id NOT IN (SELECT $ug_gid FROM $ug_rel WHERE $ug_uid=$q_uid)") or ETVPN::Cli::die_error('database error adding user/group membership: '.$DBI::errstr);
		$changed = 1 if $mod ne '0E0';
	}
	if (@remove_from_groups) {
		# remove from group(s)
		my $q_remove_from_groups = join(',', map { $dbh->quote($_) } @remove_from_groups);
		my $mod = $dbh->do("DELETE FROM $ug_rel WHERE $ug_uid=$q_uid AND $ug_gid IN (SELECT $g_id FROM $g_table WHERE $g_name IN ($q_remove_from_groups))") or ETVPN::Cli::die_error('database error removing user/group membership: '.$DBI::errstr);
		$changed = 1 if $mod ne '0E0';
	}
	return $changed;
}

sub set_subgroups($) {
	return 0 unless $no_groups || @add_to_groups || @remove_from_groups;
	ETVPN::Cli::die_error("SQL realm \"$realm\" does not have a defined \"groups table\" therefore group management can't be performed for this realm") unless $bconf->isdef('groups table');
	ETVPN::Cli::die_error("Conflicting options: --no-groups and --add-to-group") if $no_groups && @add_to_groups;
	my $q_gid = $dbh->quote(shift);
	my $sg_rel = $bconf->val('subgroups relation table');
	my $sg_child_id = $bconf->val('subgroups child id');
	if ($no_groups) {
		my $mod = $dbh->do("DELETE FROM $sg_rel WHERE $sg_child_id=$q_gid") or ETVPN::Cli::die_error('database error clearing subgroup membership: '.$DBI::errstr);
		return $mod ne '0E0';
	}
	return 0 unless check_groups();
	my $sg_parent_id = $bconf->val('subgroups parent id');
	my $g_table = $bconf->val('groups table');
	my $g_id = $bconf->val('groups col id');
	my $g_name = $bconf->val('groups col name');
	my $changed = 0;
	if (@add_to_groups) {
		# add to subgroup(s)
		my $q_add_subgroups = join(',', map { $dbh->quote($_) } grep { if ($_ eq $groupname) { warn "WARNING: skipping setting the group as part of itself\n"; 0 } else { 1 } } @add_to_groups);
		my $mod = $dbh->do("INSERT INTO $sg_rel ($sg_parent_id,$sg_child_id) SELECT $g_id,$q_gid FROM $g_table WHERE $g_name IN ($q_add_subgroups) AND $g_id NOT IN (SELECT $sg_parent_id FROM $sg_rel WHERE $sg_child_id=$q_gid)") or ETVPN::Cli::die_error('database error adding subgroup membership: '.$DBI::errstr);
		$changed = 1 if $mod ne '0E0';
	}
	if (@remove_from_groups) {
		# remove from subgroup(s)
		my $q_remove_from_groups = join(',', map { $dbh->quote($_) } @remove_from_groups);
		my $mod = $dbh->do("DELETE FROM $sg_rel WHERE $sg_child_id=$q_gid AND $sg_parent_id IN (SELECT $g_id FROM $g_table WHERE $g_name IN ($q_remove_from_groups))") or ETVPN::Cli::die_error('database error removing subgroup membership: '.$DBI::errstr);
		$changed = 1 if $mod ne '0E0';
	}
	return $changed;
}


# TODO: support modification time? would have to implement it in ETVPN::Backend::SQL->update_user_secret too...
# sub isodate($) {
# 	return strftime('%Y-%m-%d %H:%M:%S', localtime($_[0]));
# }


###############
# Command Line
###############
my @cl_errors;
GetOptions (
	'h|help' => \$need_help,
	'c|config-file=s' => \$config_file,
	'routes' => \$list_routes,
	'subgroups' => \$list_subgroups,
	'users' => \$list_users,
	'add-to-group=s' => \@add_to_groups,
	'remove-from-group=s' => \@remove_from_groups,
	'no-groups' => \$no_groups,
	'ipv4-address=s' => \$ipv4_address,
	'no-ipv4-address' => \$no_ipv4_address,
	'ipv6-address=s' => \$ipv6_address,
	'no-ipv6-address' => \$no_ipv6_address,
	'add-ipv4-route=s' => \@add_ipv4_routes,
	'remove-ipv4-route=s' => \@remove_ipv4_routes,
	'no-ipv4-routes' => \$no_ipv4_routes,
	'add-ipv6-route=s' => \@add_ipv6_routes,
	'remove-ipv6-route=s' => \@remove_ipv6_routes,
	'no-ipv6-routes' => \$no_ipv6_routes,
) or push @cl_errors, "Invalid parameters.";
unless ( defined($command = shift @ARGV ) ) {
	push @cl_errors, "Missing command.";
}
else {
	my %valid_commands = map { $_ => 1 } (
		'userlist', 'usershow', 'useradd', 'userdel', 'usermod', 'passwd', 'lock', 'unlock',
		'grouplist', 'groupshow', 'groupadd', 'groupdel', 'groupmod', 'grouprename',
	);
	if (!exists($valid_commands{$command})) {
		push @cl_errors, "Invalid command: $command";
	}
	else {
		$objectname = shift @ARGV;
		my $extraarg = shift @ARGV;
		if ($command !~ '^(?:user|group)list$' && !defined($objectname)) {
			 push @cl_errors, "Missing argument.";
		}
		elsif ($command eq 'grouprename') {
			$newname = $extraarg;
			$extraarg = undef;
			push @cl_errors, "Missing new name." unless defined($newname);
		}
		if (defined($extraarg)) {
			push @cl_errors, "Invalid extra argument: $extraarg";
		}
		if ($command ne 'grouplist') {
			push @cl_errors, '--routes is not valid in this context' if $list_routes;
			push @cl_errors, '--subgroups is not valid in this context' if $list_subgroups;
			push @cl_errors, '--users is not valid in this context' if $list_users;
		}
	}
}
if (@cl_errors) {
	print join("\n", @cl_errors)."\n\n";
	$need_help = 1;
}
help if $need_help;
$conf = ETVPN::Conf->new($config_file);


##############
# Perform actions
###############
if ($command =~ /^(?:user|group)list$/) {
	if (defined($objectname)) {
		($listpattern, $realm) = $objectname =~ /^([^@]*)(?:@(.+))?/;
	}
	get_backend_realm($realm);
}
elsif ($command =~ /^group/) {
	if (defined($objectname)) {
		($groupname, $realm) = $objectname =~ /^([^@]*)(?:@(.+))?/;
	}
	get_backend_realm($realm);
}
else {
	my $backend_realm = $conf->get_username_backend_realm($objectname) or ETVPN::Cli::die_error("Unknown realm for user $objectname");
	($backend, $username, $realm) = @$backend_realm;
}
ETVPN::Cli::die_error("Realm \"$realm\" does not correspond to a SQL backend") unless $backend->isa('ETVPN::Backend::SQL');

$bconf = $backend->get_conf();
if ($command =~ /^group/ && !$bconf->isdef('groups table')) {
	ETVPN::Cli::die_error("SQL realm \"$realm\" does not have a defined \"groups table\" therefore group management can't be performed for this realm");
}

# Ask for credentials (if the realm needs admin credentials) only for non-readonly commands
if ($command !~ /^(?:user|group)(?:list|show)$/) {
	get_credentials();
}

$dbh = $backend->db_object() or ETVPN::Cli::die_error($backend->get_error);
$username .= "\@$realm" if defined($username) && $bconf->is_true('auth append realm');

if ($command eq 'userlist') {
	my @header = (
		'Username',
		'MFA Challenge'
	);
	my @colkeys = (
		'name',
		'challenge'
	);
	my @cols = (
		$bconf->val('users col name')." AS name",
		'CASE WHEN '.$bconf->val('users col challenge')." IS NULL THEN 'No' ELSE 'Yes' END AS challenge"
	);
	if ($bconf->isdef('users col ipv4 address')) {
		push @header, 'IPv4 Address';
		push @colkeys, 'ipv4_addr';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv4 address').",'-') AS ipv4_addr";
	}
	if ($bconf->isdef('users col ipv6 address')) {
		push @header, 'IPv6 Address';
		push @colkeys, 'ipv6_addr';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv6 address').",'-') AS ipv6_addr";
	}
	my $has_ipv4_routes;
	if ($bconf->isdef('users col ipv4 routes')) {
		push @header, 'IPv4 Routes';
		push @colkeys, 'ipv4_routes';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv4 routes').",'-') AS ipv4_routes";
		$has_ipv4_routes = 1;
	}
	else {
		$has_ipv4_routes = 0;
	}
	my $has_ipv6_routes;
	if ($bconf->isdef('users col ipv6 routes')) {
		push @header, 'IPv6 Routes';
		push @colkeys, 'ipv6_routes';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv6 routes').",'-') AS ipv6_routes";
		$has_ipv6_routes = 1;
	}
	else {
		$has_ipv6_routes = 0;
	}
	my $where;
	my @params;
	if (defined($listpattern) && $listpattern ne '') {
		$where = ' WHERE '.$bconf->val('users col name').' LIKE ?';
		push @params, $listpattern;
	}
	else {
		$where = '';
	}
	my $query = 'SELECT '.join(',', @cols).' FROM '.$bconf->val('users table')."$where ORDER BY 1";
	my $sth = $dbh->prepare($query) or ETVPN::Cli::die_error('Database query preparation failed: '.$DBI::errstr);
	$sth->execute(@params) or ETVPN::Cli::die_error('Database query execution failed: '.$DBI::errstr);
	my @show;
	while (my $row = $sth->fetchrow_hashref) {
		if ($has_ipv4_routes) {
			$row->{'ipv4_routes'} = [ split(/\s*[\s,]\s*/, $row->{'ipv4_routes'}) ];
		}
		if ($has_ipv6_routes) {
			$row->{'ipv6_routes'} = [ split(/\s*[\s,]\s*/, $row->{'ipv6_routes'}) ];
		}
		my @line;
		foreach my $colkey (@colkeys) {
			push @line, $row->{$colkey};
		}
		push @show, \@line;
	}
	if (@show) {
		unshift @show, \@header;
		ETVPN::Cli::output_table(\@show, 2);
	}
	else {
		print 'No users found' . (defined($listpattern) ? ' matching selected criteria' : '') . " on SQL database of realm \"$realm\"\n";
	}
}
elsif ($command eq 'usershow') {
	my @fields = (
		'ID',
		'Multi-Factor Authentication',
	);
	my @cols = (
		$bconf->val('users col id'),
		'CASE WHEN '.$bconf->val('users col challenge')." IS NULL THEN 'No' ELSE 'Yes' END"
	);
	if ($bconf->isdef('users col ipv4 address')) {
		push @fields, 'IPv4 Address';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv4 address').",'-')";
	}
	if ($bconf->isdef('users col ipv6 address')) {
		push @fields, 'IPv6 Address';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv6 address').",'-')";
	}
	if ($bconf->isdef('users col ipv4 routes')) {
		push @fields, 'IPv4 Routes';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv4 routes').",'-')";
	}
	if ($bconf->isdef('users col ipv6 routes')) {
		push @fields, 'IPv6 Routes';
		push @cols, 'COALESCE ('.$bconf->val('users col ipv6 routes').",'-')";
	}
	# If user is duplicate, we want to detect it and issue a warning, and we also want to use SQL coalesce and case statements
	# For that reason, we don't use the $backend->userdata_from_db() method in 'show' command
	my $query = 'SELECT '.join(',', @cols).' FROM '.$bconf->val('users table').' WHERE '.$bconf->val('users col name').'=?';
	my $sth = $dbh->prepare($query) or ETVPN::Cli::die_error('Database query preparation failed: '.$DBI::errstr);
	$sth->execute($username) or ETVPN::Cli::die_error('Database query execution failed: '.$DBI::errstr);
	my $row = $sth->fetchrow_arrayref() or ETVPN::Cli::die_error("username \"$objectname\" not found on database");
	my $count = 0;
	my @show = (['Username', $objectname], ['Realm', $realm]);
	do {
		ETVPN::Cli::issue_warn("WARNING: multiple entries found for this username!") if $count == 2;
		my $ea = each_array(@fields, @$row);
		while ( my ($field, $value) = $ea->() ) {
			push @show, [$field, $value];
		}
		if ($bconf->isdef('groups table')) {
			my $groups = $dbh->selectcol_arrayref('SELECT '.$bconf->val('groups col name').' FROM '.$bconf->val('groups table').' WHERE '.$bconf->val('groups col id').' IN (SELECT '.$bconf->val('users groups group id').' FROM '.$bconf->val('users groups relation table').' WHERE '.$bconf->val('users groups user id').'='.$dbh->quote($row->[0]).') ORDER BY 1 ASC') or ETVPN::Cli::die_error('Database group membership query failed: '.$DBI::errstr);
			push @show, ['Groups', @$groups ? join(' ', @$groups) : '-'];
		}
		$count++;
	} while ($row = $sth->fetchrow_arrayref());
	ETVPN::Cli::output_table(\@show, 4);
}
elsif ($command eq 'useradd') {
	validate_new_name($username);
	my $exists = $dbh->selectcol_arrayref('SELECT COUNT(1) FROM '.$bconf->val('users table').' WHERE '.$bconf->val('users col name').'='.$dbh->quote($username)) or ETVPN::Cli::die_error('Failed querying database while validating user existance with same username: '.$DBI::errstr);
	ETVPN::Cli::die_error("User \"$username\" already exists") if $exists->[0];
	my @cols = ($bconf->val('users col name'));
	my @values = ($username);
	fill_ip_options(undef, 'users', \@cols, \@values);
	push @cols, $bconf->val('users col password');
	push @values, ask_crypt_newpassword();
	my $insert_query = 'INSERT INTO ' . $bconf->val('users table').' ('.join(',', @cols).') VALUES ('.join(',', map { $dbh->quote($_) } @values).')';
	$dbh->do($insert_query) or ETVPN::Cli::die_error('database insert query failed: '.$DBI::errstr);
	print "User $username added to SQL database of realm \"$realm\"\n";
	set_user_groups(user_dbid());
}
elsif ($command eq 'userdel') {
	my $db_id = user_dbid();
	if ($bconf->isdef('groups table')) {
		my $result_m = $dbh->do('DELETE FROM '.$bconf->val('users groups relation table').' WHERE '.$bconf->val('users groups user id').'='.$dbh->quote($db_id));
		if ($result_m ne '0E0') {
			print "Deleted $result_m group membership".($result_m == 1 ? '' : 's')." from SQL database of realm \"$realm\"\n";
		}
	}
	my $result = $dbh->do('DELETE FROM '.$bconf->val('users table').' WHERE '.$bconf->val('users col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database delete query failed: '.$DBI::errstr);
	$result = 0 if $result eq '0E0';
	print "Deleted $result user ".($result == 1 ? 'entry' : 'entries')." from SQL database of realm \"$realm\"\n";
}
elsif ($command eq 'usermod') {
	my $db_id = user_dbid();
	my @cols;
	my @values;
	my $changed = fill_ip_options($db_id, 'users', \@cols, \@values);
	ETVPN::Cli::die_error('need at least one option to modify') unless (@cols || @add_to_groups || @remove_from_groups || $no_groups);
	if (@cols) {
		my @set_vals;
		my $ea = each_array(@cols, @values);
		while ( my ($col, $value) = $ea->() ) {
			push @set_vals, "$col=".$dbh->quote($value);
		}
		my $mod = $dbh->do('UPDATE '.$bconf->val('users table').' SET '.join(',', @set_vals).' WHERE '.$bconf->val('users col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database update query failed: '.$DBI::errstr);
		$changed = 1 if $mod ne '0E0';
	}
	$changed = 1 if set_user_groups($db_id);
	my $performed = $changed ? 'Updated options' : 'No changes made';
	print "$performed for user \"$username\" with ID $db_id on SQL database of realm \"$realm\"\n";
}
elsif ($command eq 'passwd') {
	my $db_id = user_dbid();
	my $result = $dbh->do('UPDATE '.$bconf->val('users table').' SET '.$bconf->val('users col password').'='.$dbh->quote(ask_crypt_newpassword()).' WHERE '.$bconf->val('users col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database update query failed: '.$DBI::errstr);
	print "Updated password for user \"$username\" with ID $db_id on SQL database of realm \"$realm\"\n";
}
elsif ($command eq 'lock') {
	my $row = $backend->userdata_from_db($username, $realm, 'id', 'password') or ETVPN::Cli::die_error($backend->get_error);
	my $crypt_pw = $row->{'password'};
	if (!defined($crypt_pw)) {
		print "Account password is NULL, not modifying\n";
	}
	elsif ($crypt_pw =~ /^!/) {
		print "Account is already locked\n";
	}
	else {
		my $db_id = $row->{'id'};
		my $result = $dbh->do('UPDATE '.$bconf->val('users table').' SET '.$bconf->val('users col password').'='.$dbh->quote("!$crypt_pw").' WHERE '.$bconf->val('users col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database update query failed: '.$DBI::errstr);
		print "Locked user account \"$username\" with ID $db_id on SQL database of realm \"$realm\"\n";
	}
}
elsif ($command eq 'unlock') {
	my $row = $backend->userdata_from_db($username, $realm, 'id', 'password') or ETVPN::Cli::die_error($backend->get_error);
	my $locked_crypt_pw = $row->{'password'};
	if (!defined($locked_crypt_pw)) {
		print "Account password is NULL, not modifying\n";
		exit;
	}
	my ($bang, $crypt_pw) = $locked_crypt_pw =~ /^(!)?(.*)/;
	if (!defined($bang) || $bang ne '!') {
		print "Account is already unlocked\n";
	}
	else {
		my $db_id = $row->{'id'};
		$crypt_pw = '' unless defined($crypt_pw);
		my $result = $dbh->do('UPDATE '.$bconf->val('users table').' SET '.$bconf->val('users col password').'='.$dbh->quote($crypt_pw).' WHERE '.$bconf->val('users col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database update query failed: '.$DBI::errstr);
		print "Unlocked user account \"$username\" with ID $db_id on SQL database of realm \"$realm\"\n";
	}
}
elsif ($command eq 'grouplist') {
	my @header = (
		'Group name'
	);
	my @colkeys = (
		'name'
	);
	my @cols = (
		$bconf->val('groups col name')." AS name"
	);
	my $has_ipv4_routes;
	my $has_ipv6_routes;
	if ($list_routes) {
		if ($bconf->isdef('groups col ipv4 routes')) {
			push @header, 'IPv4 Routes';
			push @colkeys, 'ipv4_routes';
			push @cols, 'COALESCE ('.$bconf->val('groups col ipv4 routes').",'-') AS ipv4_routes";
			$has_ipv4_routes = 1;
		}
		else {
			$has_ipv4_routes = 0;
		}
		if ($bconf->isdef('groups col ipv6 routes')) {
			push @header, 'IPv6 Routes';
			push @colkeys, 'ipv6_routes';
			push @cols, 'COALESCE ('.$bconf->val('groups col ipv6 routes').",'-') AS ipv6_routes";
			$has_ipv6_routes = 1;
		}
		else {
			$has_ipv6_routes = 0;
		}
		ETVPN::Cli::die_error('--routes can only be used if ipv4 or ipv6 groups column option is defined in your configuration') unless ($has_ipv4_routes || $has_ipv6_routes);
	}
	if ($list_subgroups || $list_users) {
		unshift @cols, $bconf->val('groups col id')." AS id";
		push @header, 'Subgroups' if $list_subgroups;
		push @header, 'Users' if $list_users;
	}
	my $where;
	my @params;
	if (defined($listpattern) && $listpattern ne '') {
		$where = ' WHERE '.$bconf->val('groups col name').' LIKE ?';
		push @params, $listpattern;
	}
	else {
		$where = '';
	}
	my $query = 'SELECT '.join(',', @cols).' FROM '.$bconf->val('groups table').$where.' ORDER BY name';
	my $sth = $dbh->prepare($query) or ETVPN::Cli::die_error('Database query preparation failed: '.$DBI::errstr);
	$sth->execute(@params) or ETVPN::Cli::die_error('Database query execution failed: '.$DBI::errstr);
	my @show;
	while (my $row = $sth->fetchrow_hashref) {
		my @line;
		if ($list_routes) {
			if ($has_ipv4_routes) {
				$row->{'ipv4_routes'} = [ split(/\s*[\s,]\s*/, $row->{'ipv4_routes'}) ];
			}
			if ($has_ipv6_routes) {
				$row->{'ipv6_routes'} = [ split(/\s*[\s,]\s*/, $row->{'ipv6_routes'}) ];
			}
		}
		foreach my $colkey (@colkeys) {
			push @line, $row->{$colkey};
		}
		if ($list_subgroups) {
			my $query_sg = 'SELECT '.$bconf->val('groups col name').' FROM '.$bconf->val('groups table').' WHERE '.$bconf->val('groups col id').' IN (SELECT '.$bconf->val('subgroups child id').' FROM '.$bconf->val('subgroups relation table').' WHERE '.$bconf->val('subgroups parent id').'=?) ORDER BY 1';
			my $sth_sg = $dbh->prepare($query_sg) or ETVPN::Cli::die_error('Database subgroup query preparation failed: '.$DBI::errstr);
			$sth_sg->execute($row->{'id'}) or ETVPN::Cli::die_error('Database subgroup query execution failed: '.$DBI::errstr);
			my @subgroups;
			while (my $row_sg = $sth_sg->fetchrow_arrayref) {
				push @subgroups, $row_sg->[0];
			}
			if (@subgroups) {
				push @line, \@subgroups;
			}
			else {
				push @line, '-';
			}
		}
		if ($list_users) {
			my $query_users = 'SELECT '.$bconf->val('users col name').' FROM '.$bconf->val('users table').' WHERE '.$bconf->val('users col id').' IN (SELECT '.$bconf->val('users groups user id').' FROM '.$bconf->val('users groups relation table').' WHERE '.$bconf->val('users groups group id').'=?) ORDER BY 1';
			my $sth_users = $dbh->prepare($query_users) or ETVPN::Cli::die_error('Database group user members query preparation failed: '.$DBI::errstr);
			$sth_users->execute($row->{'id'}) or ETVPN::Cli::die_error('Database group user members query execution failed: '.$DBI::errstr);
			my @users;
			while (my $row_users = $sth_users->fetchrow_arrayref) {
				push @users, $row_users->[0];
			}
			if (@users) {
				push @line, \@users;
			}
			else {
				push @line, '-';
			}
		}
		push @show, \@line;
	}
	if (@show) {
		unshift @show, \@header;
		ETVPN::Cli::output_table(\@show, 2);
	}
	else {
		print 'No groups found' . (defined($listpattern) ? ' matching selected criteria' : '') . " on SQL database of realm \"$realm\"\n";
	}
}
elsif ($command eq 'groupshow') {
	my @fields = (
		'ID'
	);
	my @cols = (
		$bconf->val('groups col id')
	);
	if ($bconf->isdef('groups col ipv4 routes')) {
		push @fields, 'IPv4 Routes';
		push @cols, 'COALESCE ('.$bconf->val('groups col ipv4 routes').",'-')";
	}
	if ($bconf->isdef('groups col ipv6 routes')) {
		push @fields, 'IPv6 Routes';
		push @cols, 'COALESCE ('.$bconf->val('groups col ipv6 routes').",'-')";
	}
	my $query = 'SELECT '.join(',', @cols).' FROM '.$bconf->val('groups table').' WHERE '.$bconf->val('groups col name').'=?';
	my $sth = $dbh->prepare($query) or ETVPN::Cli::die_error('Database query preparation failed: '.$DBI::errstr);
	$sth->execute($groupname) or ETVPN::Cli::die_error('Database query execution failed: '.$DBI::errstr);
	my $row = $sth->fetchrow_arrayref() or ETVPN::Cli::die_error("groupname \"$objectname\" not found on database");
	my $count = 0;
	my @show = (['Name', $objectname], ['Realm', $realm]);
	do {
		ETVPN::Cli::issue_warn("WARNING: multiple entries found for this group!") if $count == 2;
		my $ea = each_array(@fields, @$row);
		while ( my ($field, $value) = $ea->() ) {
			push @show, [$field, $value];
		}
		my $q_gid = $dbh->quote($row->[0]);
		my $users = $dbh->selectcol_arrayref('SELECT '.$bconf->val('users col name').' FROM '.$bconf->val('users table').' WHERE '.$bconf->val('users col id').' IN (SELECT '.$bconf->val('users groups user id').' FROM '.$bconf->val('users groups relation table').' WHERE '.$bconf->val('users groups group id')."=$q_gid)") or ETVPN::Cli::die_error('Database user group membership query failed: '.$DBI::errstr);
		push @show, ['Users', @$users ? join(' ', @$users) : '-'];
		my $g_table = $bconf->val('groups table');
		my $g_col_name = $bconf->val('groups col name');
		my $g_col_id = $bconf->val('groups col id');
		my $sg_rel = $bconf->val('subgroups relation table');
		my $sg_parent_id = $bconf->val('subgroups parent id');
		my $sg_child_id = $bconf->val('subgroups child id');
		my $parent_groups = $dbh->selectcol_arrayref("SELECT $g_col_name FROM $g_table WHERE $g_col_id IN (SELECT $sg_parent_id FROM $sg_rel WHERE $sg_child_id=$q_gid)") or ETVPN::Cli::die_error('Database parent groups query failed: '.$DBI::errstr);
		push @show, ['Subgroup Of', @$parent_groups ? join(' ', @$parent_groups) : '-'];
		my $subgroups = $dbh->selectcol_arrayref("SELECT $g_col_name FROM $g_table WHERE $g_col_id IN (SELECT $sg_child_id FROM $sg_rel WHERE $sg_parent_id=$q_gid)") or ETVPN::Cli::die_error('Database subgroups query failed: '.$DBI::errstr);
		push @show, ['Subgroups', @$subgroups ? join(' ', @$subgroups) : '-'];
		$count++;
	} while ($row = $sth->fetchrow_arrayref());
	ETVPN::Cli::output_table(\@show, 4);
}
elsif ($command eq 'groupadd') {
	validate_new_name($groupname);
	my $exists = $dbh->selectcol_arrayref('SELECT COUNT(1) FROM '.$bconf->val('groups table').' WHERE '.$bconf->val('groups col name').'='.$dbh->quote($groupname)) or ETVPN::Cli::die_error('Failed querying database while validating group existance with same groupname: '.$DBI::errstr);
	ETVPN::Cli::die_error("Group \"$groupname\" already exists") if $exists->[0];
	my @cols = ($bconf->val('groups col name'));
	my @values = ($groupname);
	fill_ip_options(undef, 'groups', \@cols, \@values);
	my $insert_query = 'INSERT INTO ' . $bconf->val('groups table').' ('.join(',', @cols).') VALUES ('.join(',', map { $dbh->quote($_) } @values).')';
	my $result = $dbh->do($insert_query) or ETVPN::Cli::die_error('database insert query failed: '.$DBI::errstr);
	print "Group $groupname added to SQL database of realm \"$realm\"\n";
	set_subgroups(group_dbid());
}
elsif ($command eq 'groupdel') {
	my $db_id = group_dbid();
	my $result_m = $dbh->do('DELETE FROM '.$bconf->val('users groups relation table').' WHERE '.$bconf->val('users groups group id').'='.$dbh->quote($db_id));
	if ($result_m ne '0E0') {
		print "Deleted $result_m group membership".($result_m == 1 ? '' : 's')." from SQL database of realm \"$realm\"\n";
	}
	my $result = $dbh->do('DELETE FROM '.$bconf->val('groups table').' WHERE '.$bconf->val('groups col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database delete query failed: '.$DBI::errstr);
	$result = 0 if $result eq '0E0';
	print "Deleted $result group ".($result == 1 ? 'entry' : 'entries')." from SQL database of realm \"$realm\"\n";
}
elsif ($command eq 'groupmod') {
	my $db_id = group_dbid();
	my @cols;
	my @values;
	my $changed = fill_ip_options($db_id, 'groups', \@cols, \@values);
	ETVPN::Cli::die_error('need at least one option to modify') unless (@cols || @add_to_groups || @remove_from_groups || $no_groups);
	if (@cols) {
		my @set_vals;
		my $ea = each_array(@cols, @values);
		while ( my ($col, $value) = $ea->() ) {
			push @set_vals, "$col=".$dbh->quote($value);
		}
		my $mod = $dbh->do('UPDATE '.$bconf->val('groups table').' SET '.join(',', @set_vals).' WHERE '.$bconf->val('groups col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database update query failed: '.$DBI::errstr);
		$changed = 1 if $mod ne '0E0';
	}
	$changed = 1 if set_subgroups($db_id);
	my $performed = $changed ? 'Updated options' : 'No changes made';
	print "$performed for group \"$groupname\" with ID $db_id on SQL database of realm \"$realm\"\n";
}
elsif ($command eq 'grouprename') {
	my $db_id = group_dbid();
	$dbh->do('UPDATE '.$bconf->val('groups table').' SET '.$bconf->val('groups col name').'='.$dbh->quote($newname).' WHERE '.$bconf->val('groups col id').'='.$dbh->quote($db_id)) or ETVPN::Cli::die_error('database update query failed: '.$DBI::errstr);
	print "Renamed for group \"$groupname\" with ID $db_id to \"$newname\" on SQL database of realm \"$realm\"\n";
}
else {
	# should not happen
	ETVPN::Cli::die_error("Internal error validating command, please contact support");
}
