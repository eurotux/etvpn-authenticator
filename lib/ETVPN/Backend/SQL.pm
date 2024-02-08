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

package ETVPN::Backend::SQL v0.7.4;
use strict;
use warnings;
use parent qw(ETVPN::Backend::Base);

use DBI;


sub need_admin_credentials {
	my $self = shift;
	return $self->get_conf()->is_true('need admin credentials');
}


sub _db_connect {
	my ($self, $db_user, $password) = @_;

	my $dbh;
	my $conf = $self->get_conf();
	$dbh = DBI->connect(
		'DBI:'.$conf->val('driver').':'.$conf->val('database parameters'),
		$db_user,
		$password,
		{ RaiseError => 0, PrintWarn => 0, PrintError => 0 }
	) or do {
		$self->add_internal_error("could not connect to SQL database related to realm ".$self->get_realm().': '.$DBI::errstr);
		return undef;
	};
	$self->set_connected($db_user);
	return $dbh;
}


sub db_object {
	my $self = shift;

	my $dbh;
	if ($self->{'dbh'}) {
		return $self->{'dbh'};
	}
	else {
		my $conf = $self->get_conf();
		$dbh = $self->{'dbh'} = $self->_db_connect($conf->val('database username'), $conf->val('database password'));

	}
	return $dbh;
}


sub connect_as {
	my ($self, $db_user, $password) = @_;

	$self->{'dbh'} = $self->_db_connect($db_user, $password) and return 1;
	return 0;
}


sub disconnect {
	my $self = shift;

	if ($self->is_connected()) {
		$self->db_object()->disconnect();
		$self->{'dbh'} = undef;
	}
}


sub _tabledata_from_db {
	my ($self, $type, $name, @col_confs) = @_;

	unless (@col_confs) {
		$self->add_internal_error("internal error: $type data from database requested without specifying columns");
		return undef;
	}
	my $dbh = $self->db_object() or return undef;
	my $conf = $self->get_conf();
	my $tkey = $type.'s';
	my $columns = join(',', map { my $col_as = $_; $col_as =~ s/\s/_/g; $conf->val("$tkey col $_") . " AS $col_as" } @col_confs);
	my $query = "SELECT $columns FROM ".$conf->val("$tkey table").' WHERE '.$conf->val("$tkey col name").'=?';
	my $sth = $dbh->prepare($query) or do {
		$self->add_internal_error('database query preparation failed while validating login: '.$DBI::errstr);
		return undef;
	};
	$sth->execute($name) or do {
		$self->add_internal_error('database query execution failed while validating login: '.$DBI::errstr);
		return undef;
	};
	my $row = $sth->fetchrow_hashref() or do {
		$self->add_error("$type \"$name\" not found on database");
		return undef;
	};
	if ($sth->fetchrow_arrayref()) {
		$self->add_internal_error("duplicate entry found on database for $type \"$name\"");
		return undef;
	}
	return $row;
}


sub userdata_from_db {
	my ($self, $user_name, $realm, @col_confs) = @_;

	$user_name .= '@'.$realm if $self->get_conf()->is_true('auth append realm');
	return $self->_tabledata_from_db('user', $user_name, @col_confs);
}


sub groupdata_from_db {
	my ($self, $group_name, @col_confs) = @_;

	return $self->_tabledata_from_db('group', $group_name, @col_confs);
}


sub is_in_group {
	my ($self, $group, $row) = @_;
	my $conf = $self->get_conf();
	my $g_table = $conf->val('groups table') or return 0;
	my $dbh = $self->db_object() or return 0;
	my $g_col_id = $conf->val('groups col id');
	my $g_col_name = $conf->val('groups col name');
	my $ug_rel = $conf->val('users groups relation table');
	my $ug_uid = $conf->val('users groups user id');
	my $ug_gid = $conf->val('users groups group id');
	my $sg_rel = $conf->val('subgroups relation table');
	my $sg_parent_id = $conf->val('subgroups parent id');
	my $sg_child_id = $conf->val('subgroups child id');
	my $res = $dbh->selectrow_arrayref("WITH RECURSIVE etvpn_all_subgroups(subgroup_id) AS ( SELECT $ug_gid FROM $ug_rel WHERE $ug_uid=".$dbh->quote($row->{'id'})." UNION SELECT $sg_child_id FROM $sg_rel,etvpn_all_subgroups WHERE $sg_parent_id=etvpn_all_subgroups.subgroup_id ) SELECT COUNT(1) WHERE EXISTS (SELECT 1 FROM $g_table WHERE $g_col_name=".$dbh->quote($group)." AND $g_col_id IN etvpn_all_subgroups)") or do {
		$self->add_internal_error("database query failed while checking membership for group \"$group\": ".$DBI::errstr);
		return 0;
	};
	return $res->[0] > 0;
}


sub get_ip_opt_val {
	my ($self, $ipver, $type, $row) = @_;

	return undef unless defined($ipver);

	my $key = 'ip'.(defined($ipver) ? "v$ipver" : '').'_';
	if ($type eq 'addr') {
		$key .= 'address';
	}
	else {
		$key .= $type;
	}

	my $addr = $row->{$key};
	if ($type eq 'routes') {
		# use a hash to avoid duplicates
		my %routes;
		# individual user routes
		if (defined($addr)) {
			%routes = map { $_ => 1 } split(/\s*[\s,]\s*/, $addr);
		}
		# routes from SQL (sub)groups the user belongs to
		my $conf = $self->get_conf();
		if ( ( my $g_table = $conf->val('groups table') ) &&
		     ( my $g_col_routes = $conf->val("groups col ipv$ipver routes") ) &&
		     ( my $dbh = $self->db_object() ) ) {
			my $g_col_id = $conf->val('groups col id');
			my $ug_rel = $conf->val('users groups relation table');
			my $ug_uid = $conf->val('users groups user id');
			my $ug_gid = $conf->val('users groups group id');
			my $sg_rel = $conf->val('subgroups relation table');
			my $sg_parent_id = $conf->val('subgroups parent id');
			my $sg_child_id = $conf->val('subgroups child id');
			my $sth = $dbh->prepare("WITH RECURSIVE etvpn_all_subgroups(subgroup_id) AS ( SELECT $ug_gid FROM $ug_rel WHERE $ug_uid=? UNION SELECT $sg_child_id FROM $sg_rel,etvpn_all_subgroups WHERE $sg_parent_id=etvpn_all_subgroups.subgroup_id ) SELECT $g_col_routes FROM $g_table WHERE $g_col_id IN etvpn_all_subgroups AND $g_col_routes IS NOT NULL");
			if ($sth && $sth->execute($row->{'id'})) {
				while ( (my $row_r = $sth->fetchrow_arrayref()) ) {
					foreach my $r (split(/\s*[\s,]\s*/, $row_r->[0])) {
						$routes{$r} = 1;
					}
				}
			}
			else {
				ETVPN::Logger::log("WARNING: database query failed while checking for group IPv$ipver routes: ".$DBI::errstr);
			}
		}
		return [ keys %routes ];
	}

	# else -> type is 'addr'
	if ($ipver == 4) {
		return $addr;
	}

	# else -> type is 'addr' and $ipver is 6
	return [$addr, undef];
}


sub _evlogin_from_userdata {
	my ($self, $user_name, $row) = @_;

	return new ETVPN::Login(
		'account name' => $user_name,
		'unique id' => $row->{'id'},
		'secret' => $row->{'challenge'},
		'static ip4' => $self->get_static_ip(4, $user_name, $row),
		'static ip6' => $self->get_static_ip(6, $user_name, $row),
		'push routes' => $self->get_static_routes(undef, $row),
		'push routes ip4' => $self->get_static_routes(4, $row),
		'push routes ip6' => $self->get_static_routes(6, $row),
	);
}


sub check_row {
	my ($self, $row, @keys) = @_;

	return 0 unless defined($row);

	foreach my $key (@keys) {
		unless (defined($row->{$key})) {
			my $col = $key;
			$col =~ s/_/ /g;
			$self->add_internal_error("user's $key value from column '".$self->get_conf()->val("users col $col")."' is undefined, PLEASE REVIEW YOUR CONFIGURATION OR CHECK YOUR DATABASE INTEGRITY");
			return 0;
		}
	};

	return 1;
}


sub check_user_password {
	my ($self, $user_name, $realm, $user_password) = @_;

	# Query mandatory and optional configured columns
	my @col_confs = ('id', 'password', 'challenge');
	my $conf = $self->get_conf();
	foreach my $ip_col_opt ('ipv4 address', 'ipv6 address', 'ipv4 routes', 'ipv6 routes') {
		push(@col_confs, $ip_col_opt) if $conf->isdef("users col $ip_col_opt");
	}

	# Fetch data from DB
	my $row = $self->userdata_from_db($user_name, $realm, @col_confs);
	return undef unless $self->check_row($row, 'id', 'password');

	# Be specific if the account is locked
	my $db_password = $row->{'password'};
	if ($db_password =~ /^\s*!/) {
		$self->add_error('account is locked');
		return undef;
	}
	# Check password
	if (crypt($user_password, $db_password) ne $db_password) {
		$self->add_error('wrong password');
		return undef;
	}

	# return ETVPN::Login object generated from database row information
	return $self->_evlogin_from_userdata($user_name, $row);
}


sub get_user_login_object {
	my ($self, $user_name, $realm, $extended) = @_;

	my @col_confs = ('id', 'challenge');
	if ($extended) {
		my $conf = $self->get_conf();
		foreach my $ip_col_opt ('ipv4 address', 'ipv6 address', 'ipv4 routes', 'ipv6 routes') {
			push(@col_confs, $ip_col_opt) if $conf->isdef("users col $ip_col_opt");
		}
	}

	my $row = $self->userdata_from_db($user_name, $realm, @col_confs);
	return undef unless $self->check_row($row, 'id');
	return $self->_evlogin_from_userdata($user_name, $row);
}


sub update_user_secret {
	my ($self, $secret_encoder, $secret_type, $user_name, $realm, $plain_secret) = @_;

	my $row = $self->userdata_from_db($user_name, $realm, 'id');
	return 0 unless $self->check_row($row, 'id');
	my $db_id = $row->{'id'};
	my $safe_secret = $secret_encoder->encode($secret_type, $db_id, $plain_secret) or do {
		$self->add_internal_error($secret_encoder->get_error());
		return 0;
	};
	my $conf = $self->get_conf();
	my $dbh = $self->db_object() or return 0;
	my $update_query = 'UPDATE '.$conf->val('users table').' SET '.$conf->val('users col challenge').'=? WHERE '.$conf->val('users col id').'=?';
	my $sth = $dbh->prepare($update_query) or do {
		$self->add_internal_error('database update query preparation failed while updating user secret: '.$DBI::errstr);
		return 0;
	};
	$sth->execute($safe_secret, $db_id) or do {
		$self->add_internal_error('database update query execution failed while updating user secret: '.$DBI::errstr);
		return 0;
	};
	return 1;
}


1;
