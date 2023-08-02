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

package ETVPN::IPPool::SQL v0.7.1;
use strict;
use warnings;
use parent qw(ETVPN::IPPool::Base);

use DBI;
use Net::IP;


sub _db_connect {
	my ($self, $db_user, $password) = @_;

	my $dbh;
	my $conf = $self->get_conf();
	$dbh = DBI->connect(
		'DBI:'.$conf->val('driver').':'.$conf->val('database parameters'),
		$db_user,
		$password,
		{ RaiseError => 0, PrintWarn => 0, PrintError => 0 }
	) or ETVPN::Logger::fatal('could not connect to IP pool SQL database: '.$DBI::errstr);
	return $dbh;
}


sub register_ovpn_instance {
	my ($self, $mgmt_address, $mgmt_port, $ovpn_pid) = @_;

	my $dbh = $self->_db_connect();
	my $q_address = $dbh->quote($mgmt_address);
	my $q_port = $dbh->quote($mgmt_port);
	my $q_ovpn_id;
	my $row = $dbh->selectrow_arrayref("SELECT id,pid FROM openvpn_instances WHERE address=$q_address AND port=$q_port");
	if ($row) {
		$q_ovpn_id = $dbh->quote($row->[0]);
		if ($ovpn_pid != $row->[1]) {
			my $purged = $dbh->do("DELETE FROM ippools_v4 WHERE openvpn_instance=$q_ovpn_id");
			unless ( defined($purged) &&
				 $dbh->do("UPDATE openvpn_instances SET pid=".$dbh->quote($ovpn_pid)." WHERE id=$q_ovpn_id") ) {
				ETVPN::Logger::fatal('error updating IP pool SQL database while registering OpenVPN instance: '.$DBI::errstr);
			}
			ETVPN::Logger::log("purged $purged address".($purged == 1 ? '' : 'es').' from IP pool') unless $purged eq '0E0';
		}
	}
	else {
		unless ($dbh->do("INSERT INTO openvpn_instances (address,port,pid) VALUES ($q_address,$q_port,".$dbh->quote($ovpn_pid).")")) {
			ETVPN::Logger::fatal('error registering OpenVPN instance in IP pool SQL database: '.$DBI::errstr);
		}
		my $last_id = $dbh->last_insert_id(undef, undef, 'openvpn_instances', 'TABLE') or ETVPN::Logger::fatal('could not retrieve newly created OpenVPN instance registration ID from IP pool SQL database');
		$q_ovpn_id = $dbh->quote($last_id);
	}
	$dbh->disconnect();
	$self->{'q_ovpn_id'} = $q_ovpn_id;
	$self->set_registered();
}


sub __ip_from_pool_offset($$) {
	my ($pool, $offset) = @_;

	my $ret = $pool + $offset;
	ETVPN::Logger::log('SQL IP pool: assigned address '.$ret->ip());
	return $ret;
}


sub get_user_pool_ip {
	my ($self, $pool, $username, $realm, $cid, $ipver) = @_;

	return undef unless $self->is_registered();

	$self->clear_error();
	my $dbh = $self->_db_connect();

	my $table = "ippools_v$ipver";
	my $q_pool = $dbh->quote($pool->print());
	my $fulluser = "$username\@$realm";
	my $q_user = $dbh->quote($fulluser);
	my $q_cid = $dbh->quote($cid);
	my $q_ovpn_id = $self->{'q_ovpn_id'};

	# check if user already has an address, if so and update record and return it
	if (defined( my $row = $dbh->selectrow_arrayref("SELECT id,pool_offset FROM $table WHERE pool=$q_pool AND username=$q_user") )) {
		my $ret;
		if ($dbh->do("UPDATE $table SET cid=$q_cid,openvpn_instance=$q_ovpn_id,updated=CURRENT_TIMESTAMP WHERE id=".$dbh->quote($row->[0]))) {
			$ret = __ip_from_pool_offset($pool, $row->[1]);
		}
		else {
			$self->add_internal_error('error updating SQL IP pool record for user \"$fulluser\": '.$DBI::errstr);
		}
		$dbh->disconnect();
		return $ret;
	}

	# reserve a free address and return it
	# TODO: add an option to emulate ifconfig-pool-linear and support p2p topology
	my $max_ofs = $pool->size() - 2;  # e.g. for a /24 which has a size of 256, max offset = 254
	my $q_mofs = $dbh->quote($max_ofs);
	my $q_mcnt = $q_mofs;
	my $ret;
	my $last_id;
	my $result = $dbh->do("INSERT INTO $table (pool,pool_offset,username,cid,openvpn_instance,updated) SELECT $q_pool,COALESCE(free_offset, 1),$q_user,$q_cid,$q_ovpn_id,CURRENT_TIMESTAMP FROM ( SELECT COUNT(1) AS c FROM $table WHERE pool=$q_pool ),( SELECT MAX(free_offset) AS free_offset FROM ( SELECT pool_offset+1 AS free_offset FROM $table WHERE pool=$q_pool AND free_offset BETWEEN 1 and $q_mofs AND free_offset NOT IN (SELECT pool_offset FROM $table WHERE pool=$q_pool) ) LIMIT 1 ) WHERE c < $q_mcnt");
	if (!$result) {
		$self->add_internal_error('error performing query to reserve a IP pool address for user \"$fulluser\": '.$DBI::errstr);
	}
	elsif ($result eq '0E0' || !( $last_id = $dbh->last_insert_id(undef, undef, $table, 'TABLE') )) {
		$self->add_internal_error("IP pool $pool exhausted while trying to reserve an address for user \"$fulluser\"");
	}
	elsif (defined( my $row = $dbh->selectrow_arrayref("SELECT pool_offset FROM $table WHERE pool=$q_pool AND id=".$dbh->quote($last_id)) )) {
		$ret = __ip_from_pool_offset($pool, $row->[0]);
	}
	else {
		$self->add_internal_error("unable to retrieve newly created SQL IP pool reserved address for user \"$fulluser\"");
	}

	$dbh->disconnect();
	return $ret;
}


sub free_user_address {
	my ($self, $cid, $ipver) = @_;

	unless ($self->is_registered()) {
		$self->add_internal_error("attempt to free address on non-registered SQL IP pool");
		return -1;
	}

	$self->clear_error();
	my $dbh = $self->_db_connect();

	my $table = "ippools_v$ipver";
	my $q_cid = $dbh->quote($cid);
	my $q_ovpn_id = $self->{'q_ovpn_id'};

	my $ret;
	my $result = $dbh->do("DELETE FROM ippools_v4 WHERE cid=$q_cid AND openvpn_instance=$q_ovpn_id");
	if (defined($result)) {
		$ret = $result eq '0E0' ? 0 : $result;
	}
	else {
		$self->add_internal_error("SQL database error while trying to free IP pool address for cid $cid");
		$ret = -1;
	}

	$dbh->disconnect();
	return $ret;
}


1;
