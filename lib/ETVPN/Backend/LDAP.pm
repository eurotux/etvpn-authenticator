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

package ETVPN::Backend::LDAP v0.7.4;
use strict;
use warnings;
use parent qw(ETVPN::Backend::Base);

use Net::LDAP;
use Net::IP qw(:PROC);


sub _opt_expand {
	my ($self, $opt, $extra_tags) = @_;
	my $conf = $self->get_conf();
	my $expanded = $conf->val($opt);
	if (defined($expanded)) {
		$extra_tags = {} unless defined($extra_tags);
		my %tags = (
			u => $self->{'user_uid'},
			R => $self->get_realm(),
			r => $self->{'user_realm'},
			g => $conf->val('ldap group'),
			b => $conf->val('ldap base'),
			%$extra_tags,
		);
		$expanded =~ s/%([uRrgbG])/exists($tags{$1}) ? $tags{$1} : "%$1"/ge;
		# expanded options must expand - sanity check to ensure no one messed up the configuration
		if ($opt eq $expanded) {
			$self->add_internal_error("invalid value $opt in LDAP backend ".$self->get_realm().": did not expand to a different result, PLEASE REVIEW CONFIGURATION");
			return undef;
		}
	}
	return $expanded;
}


sub _ldap_object {
	my $self = shift;
	my $ldap;
	if ($self->{'ldap'}) {
		return $self->{'ldap'};
	}
	else {
		my $conf = $self->get_conf();
		$ldap = $self->{'ldap'} = Net::LDAP->new($conf->val('ldap address'), timeout => $conf->val('ldap timeout')) or do {
			$self->add_internal_error("could not create LDAP connection: $@");
			return undef;
		};
	}
	return $ldap;
}


sub _search_user_dn_using_ldap {
	my ($self, $user_name) = @_;

	# This method assumes LDAP bind is already made
	my $ldap = $self->_ldap_object() or return undef;

	my $filter = $self->_opt_expand('ldap dn filter') or return undef;
	my $srch = $ldap->search(
		base   => $self->get_conf()->val('ldap base'),
		filter => $filter
	);
	if ($srch->code) {
		$self->add_internal_error("LDAP search or filter error while searching user DN: ".$srch->error_name);
		return undef;
	}
	if ($srch->entries == 0) {
		$self->add_error("invalid user on LDAP realm ".$self->get_realm().": $user_name");
		return undef;
	}
	if ($srch->entries != 1) {
		$self->add_internal_error('critical error: found more than one matching DN - please review your ldap dn filter option');
		return undef;
	}

	return $srch->entry(0)->dn;
}


sub _find_user_bind_name {
	my ($self, $user_name, $realm) = @_;

	$self->{'user_uid'} = $user_name;
	$self->{'user_realm'} = $realm;
	my $ldap_user;
	my $conf = $self->get_conf();
	if ($conf->is_true('auth append realm')) {
		$ldap_user = "$user_name\@$realm";
	}
	else {
		# find user DN
		my $user_dn;
		my $search_via_ldap = 0;
		my $connected_as_system_user = 0;
		if ($self->is_connected()) {
			$search_via_ldap = 1;
		}
		elsif ($conf->isdef('ldap bind dn') && $conf->isdef('ldap bind password')) {
			my $ldap = $self->_ldap_object() or return undef;
			my $mesg = $ldap->bind($conf->val('ldap bind dn'), password => $conf->val('ldap bind password'));
			if ($mesg->code) {
				$self->add_internal_error('failed finding user DN with error '.$mesg->error_name.' - please review your server ldap bind dn and ldap bind password configuration options');
			}
			$search_via_ldap = 1;
			$connected_as_system_user = 1;
		}

		if ($search_via_ldap) {
			$user_dn = $self->_search_user_dn_using_ldap($user_name);
			# important: ensure ldap is logged out if we connected as system user to search for the DN
			$self->_logout() if $connected_as_system_user;
		}
		elsif ($conf->isdef('ldap bind dn format')) {
			# derive user DN from format in config
			$user_dn = $self->_opt_expand('ldap bind dn format');
		}
		else {
			# consider invalid user since in AD we need to enforce user@domain or user\domain login syntax
			$self->add_error('invalid user');;
		}

		$ldap_user = $user_dn;
	}

	return $ldap_user;
}


sub connect_as {
	my ($self, $ldap_user, $password) = @_;

	my $ldap = $self->_ldap_object() or return 0;

        my $mesg = $ldap->bind($ldap_user, password => $password);
	if ($mesg->code) {
		$self->add_error($mesg->error_name);
		return 0;
	}
	$self->set_connected($ldap_user);
	return 1;
}


sub _logout {
	my $self = shift;

	# Don't use _ldap_object here on purpose, since we only care if it exists
	if ( (my $ldap = $self->{'ldap'}) ) {
		$ldap->unbind;
		delete $self->{'connected_as'};
	}
}


sub disconnect {
	my $self = shift;

	$self->_logout();
	delete $self->{'ldap'} if $self->{'ldap'};
	delete $self->{'user_uid'} if $self->{'user_uid'};
	delete $self->{'user_realm'} if $self->{'user_realm'};
	delete $self->{'user_secret'} if $self->{'user_secret'};
}


sub _get_last_user_entry_from_login_filter() {
	my $self = shift;

	my $ldap = $self->_ldap_object() or return undef;

	# search for user entry while ensuring mandatory login filter (e.g. group membership)
	my $filter = $self->_opt_expand('ldap login filter') or return undef;
	my $entry;
	my $srch = $ldap->search(
		base   => $self->get_conf()->val('ldap base'),
		filter => $filter
	);
	if ($srch->code) {
		$self->add_internal_error("LDAP search or filter error while checking login filter: ".$srch->error_name);
	}
	elsif ($srch->entries != 1) {
		$self->add_error('user is invalid or failed login filter check');
	}
	else {
		$entry = $srch->entry(0);
	}

	return $entry;
}


sub is_in_group {
	my ($self, $group, $entry) = @_;

	my $filter = $self->_opt_expand('ldap group membership filter', { G => $group }) or return 0;
	my $ldap = $self->_ldap_object() or return 0;
	my $srch = $ldap->search(
		base   => $self->get_conf()->val('ldap base'),
		filter => $filter
	);
	if ($srch->code) {
		$self->add_internal_error("LDAP search or filter error while checking group membership: ".$srch->error_name);
		return 0;
	}
	elsif ($srch->entries > 1) {
		$self->add_internal_error("LDAP group membership query returned more than one result, treating it as CONFIGURATION ERROR - please review your ldap group membership filter option");
		return 0;
	}
	return $srch->entries == 1;
}


sub get_ip_opt_val {
	my ($self, $ipver, $type, $entry) = @_;

	my $conf_opt = "ldap ip".(defined($ipver) ? "v$ipver" : '').' ';
	if ($type eq 'addr') {
		$conf_opt .= 'static address';
	}
	else {
		$conf_opt .= $type;
	}
	my $conf = $self->get_conf();
	return undef unless $conf->isdef($conf_opt);

	my $attr = $conf->val($conf_opt);
	if ($type eq 'routes') {
		return $entry->get_value($attr, asref => 1);
	}

	# else -> type is 'addr'
	my $addr = $entry->get_value($attr);
	if ($ipver == 4) {
		return undef unless defined($addr);
		my $fmt = $conf->val('ldap ipv4 static address format');
		if (defined($fmt) && $fmt eq 'int') {
			my $conv_addr = ip_bintoip(unpack('B32', pack 'N', $addr), 4) or do {
				ETVPN::Logger::log("WARNING: ignoring invalid static IPv4 address $addr from integer type LDAP attribute '$attr'");
				return undef;
			};
			return $conv_addr;
		}
		else {
			# 'ldap ipv4 static address format' is text
			return $addr;
		}
	}

	# else -> type is 'addr' and $ipver is 6
	my $ifid;
	if ( defined(my $attr_ifid = $conf->val('ldap ipv6 static address interface id')) ) {
		$ifid = $entry->get_value($attr_ifid);
	}
	return [$addr, $ifid];
}


sub _evlogin_from_entry {
	my ($self, $entry) = @_;

	my $conf = $self->get_conf();
	my $unique_id = $conf->isdef('ldap unique identifier') ? $entry->get_value($conf->val('ldap unique identifier')) : undef;
	my $secret;
	if ($conf->isdef('ldap challenge field')) {
		$secret = $entry->get_value($conf->val('ldap challenge field'));
		if (!defined($unique_id)) {
			$self->add_internal_error("user's LDAP unique ID attribute '".$conf->val('ldap unique id')."' is undefined, PLEASE REVIEW YOUR CONFIGURATION OR CHECK YOUR LDAP INTEGRITY");
			return undef;
		}
	}
	my $account_name = $entry->get_value($conf->val('ldap account name'));
	if (!defined($account_name)) {
		$self->add_internal_error("user's LDAP account name '".$conf->val('ldap account name')."' is undefined, PLEASE REVIEW YOUR CONFIGURATION OR CHECK YOUR LDAP INTEGRITY");
		return undef;
	}

	return new ETVPN::Login(
		'account name' => $account_name,
		'unique id' => $unique_id,
		'secret' => $secret,
		'static ip4' => $self->get_static_ip(4, $account_name, $entry),
		'static ip6' => $self->get_static_ip(6, $account_name, $entry),
		'push routes' => $self->get_static_routes(undef, $entry),
		'push routes ip4' => $self->get_static_routes(4, $entry),
		'push routes ip6' => $self->get_static_routes(6, $entry),
	);
}


sub check_user_password {
	my ($self, $user_name, $realm, $user_password) = @_;

	# find corresponding username for binding
	my $ldap_user = $self->_find_user_bind_name($user_name, $realm) or do {
		return undef;
	};

	# validate credentials by binding to LDAP as the user
	unless ($self->connect_as($ldap_user, $user_password)) {
		return undef;
	}

	# validate login filter and obtain user LDAP entry
	my $entry = $self->_get_last_user_entry_from_login_filter() or return undef;

	# return ETVPN::Login object generated from LDAP entry
	return $self->_evlogin_from_entry($entry);
}


sub get_user_login_object {
	my ($self, $user_name, $realm, $extended) = @_;

	# clear any errors caused by previous attempts
	$self->clear_error();

	if ($self->_find_user_bind_name($user_name, $realm) &&
	    ( my $entry = $self->_get_last_user_entry_from_login_filter() )) {
		return $self->_evlogin_from_entry($entry);
	}
	return undef;
}


sub update_user_secret {
	my ($self, $secret_encoder, $secret_type , $user_name, $realm, $plain_secret) = @_;

	my $conf = $self->get_conf();
	unless ($conf->isdef('ldap challenge field')) {
		$self->add_internal_error("configuration item 'ldap challenge field' must be defined to store a secret on LDAP backend");
		return 0;
	}

	# clear any errors caused by previous attempts
	$self->clear_error();

	if ( ( my $ldap = $self->_ldap_object() ) &&
	     $self->_find_user_bind_name($user_name, $realm) &&
	     ( my $entry = $self->_get_last_user_entry_from_login_filter() ) ) {
		# ETVPN::Conf has already validated that 'ldap unique identifier' must be set when 'ldap challenge field' is also set
		my $unique_id = $entry->get_value($conf->val('ldap unique identifier'));
		my $safe_secret = $secret_encoder->encode($secret_type, $unique_id, $plain_secret) or do {
			$self->add_internal_error($secret_encoder->get_error());
			return 0;
		};
		$entry->replace( $conf->val('ldap challenge field') => $safe_secret );
		my $mesg = $entry->update($ldap);
		if ($mesg->code) {
			$self->add_internal_error($mesg->error_name);
		}
		else {
			return 1;
		}
	}
	return 0;
}


1;
