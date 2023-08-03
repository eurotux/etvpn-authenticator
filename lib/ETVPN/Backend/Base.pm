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

package ETVPN::Backend::Base v0.7.2;
use strict;
use warnings;
use parent qw(ETVPN::Actionable);

use Scalar::Util 'refaddr';
use Net::IP;
use ETVPN::Logger;
use ETVPN::Login;
use ETVPN::Util;


my $old_sigpipe_handler;
my $our_class_sigpipe_handler;
my %sigpipe_handlers;


sub new {
	my ($class, $conf, $realm) = @_;

	my $self = $class->SUPER::new($conf);
	$self->{'realm'} = $realm;

	# trap SIGPIPE so that daemon doesn't die if backend connection was timed out on server side
	$sigpipe_handlers{$self} = sub { $self->handle_sigpipe(); };
	# only override the SIGPIPE handler if it isn't already globally defined
	if (!$SIG{PIPE} || $SIG{PIPE} eq 'DEFAULT') {
		$old_sigpipe_handler = $SIG{PIPE};
		$SIG{PIPE} = $our_class_sigpipe_handler = sub { _class_handle_sigpipe(); };
	}

	return $self;
}


sub DESTROY {
	my $self = shift;

	delete($sigpipe_handlers{$self});
	if (!%sigpipe_handlers) {
		# last instance of this class, restore SIGPIPE handler but do so only if it is still the same we set
		if (defined($our_class_sigpipe_handler) && $SIG{PIPE} && $SIG{PIPE} ne 'DEFAULT' && refaddr($SIG{PIPE}) == refaddr($our_class_sigpipe_handler)) {
			$SIG{PIPE} = $old_sigpipe_handler;
		}
		$our_class_sigpipe_handler = $old_sigpipe_handler = undef;
	}

	$self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}


sub handle_sigpipe {
	# by default ignore the signal, each call should handle itself
	# however should any subclass need, it can override the method
	1;
}


sub _class_handle_sigpipe {
	# call method for each instance
	foreach (keys %sigpipe_handlers) {
		&{$sigpipe_handlers{$_}}();
	}
}


sub validate_login {
	my ($self, $user_name, $realm, $user_password) = @_;

	# clear any errors caused by previous attempts
	$self->clear_error();

	# ensure no previous stale connections are left
	# also don't try reusing existing Sconnection between attempts since the backend server may have closed it
	# any subclasses wanting to override this behaviour should override this method, or work some logic in the disconnect() one
	$self->disconnect();

	# get response object
	my $login = $self->check_user_password($user_name, $realm, $user_password);
	if (defined($login)) {
		$login->set_success(1);
		$login->set_realm($realm);
	}

	# don't leave stale connections
	$self->disconnect();

	return $login;
}


sub set_connected {
	my ($self, $connected_as) = @_;

	$self->{'connected_as'} = $connected_as;
}


sub is_connected {
	my $self = shift;

	return defined($self->{'connected_as'});
}


sub get_realm {
	my $self = shift;

	return $self->{'realm'};
}


sub get_static_routes {
	my ($self, $ipver, $data) = @_;

	my $ret_routes = {};

	# Add user individual routes
	my $route_values = $self->get_ip_opt_val($ipver, 'routes', $data);
	if (defined($route_values) && @$route_values) {
		my @user_ip_routes;
		foreach my $route (@$route_values) {
			# support lists that start with IP address, but ignore what comes after (like some LDAP entries)
			# TODO: does it make sense to do something with the gateway and the metrics? perhaps with new options like "include push gateways" and "exclude push gateways"? or force to provide a gateway filter in a regexp with capture parenthesis?
			my ($addr) = $route =~ /^(\S+)/ or next;
			my $ip = new Net::IP($addr) or do {
				ETVPN::Logger::log("WARNING: ignoring invalid push route address $addr");
				next;
			};
			if ($ipver && $ip->version != $ipver) {
				ETVPN::Logger::log("WARNING: ignoring invalid push route address $addr (expected IPv$ipver address, got a IPv".$ip->version." address)");
				next;
			}
			push @user_ip_routes, $ip;
		}
		$ret_routes = ETVPN::Util::add_new_ip_objects($ret_routes, \@user_ip_routes);
	}

	unless (defined($ipver)) {
		# Add config file static routes, eliminating duplicates
		my $conf = $self->get_conf();
		$ret_routes = { %$ret_routes, %{$conf->get_routes()} };
		# Add config file group static routes, eliminating duplicates
		my $conf_group_routes = $conf->get_group_routes();
		foreach my $group (keys %$conf_group_routes) {
			if ($self->is_in_group($group, $data)) {
				$ret_routes = { %$ret_routes, %{$conf_group_routes->{$group}} };
			}
		}
	}

	if ($self->has_internal_error()) {
		ETVPN::Logger::log('WARNING: internal error: '.$self->get_error());
	}

	# The return value is a hash reference whose elements are of the form 'ip_short/prefix' => Net::IP
	return $ret_routes;
}


sub get_static_ip {
	my ($self, $ipver, $username, $data) = @_;

	my $ip_val = $self->get_ip_opt_val($ipver, 'addr', $data);
	if ($ipver == 4) {
		my $ip;
		if (defined($ip_val)) {
			# User static IP address
			$ip = new Net::IP("$ip_val/32", 4) or ETVPN::Logger::log("WARNING: ignoring invalid static IPv4 address $ip_val");
		}
		else {
			# IP pool net, if it exists
			my $conf = $self->get_conf();
			if (defined( my $ippool = $conf->get_ip_pool() )) {
				my $conf_group_ip_pools = $conf->get_group_ip_pools($ipver);
				foreach my $group (keys %$conf_group_ip_pools) {
					if ($self->is_in_group($group, $data)) {
						return $conf_group_ip_pools->{$group};
					}
				}
			}
		}
		return $ip;
	}

	# else $ipver is 6
	return undef unless defined($ip_val);
	my ($addr, $ifid) = @$ip_val;
	return undef unless defined($addr) || defined($ifid);
	my $ret = [undef, undef];
	if (defined($addr)) {
		my $ip = new Net::IP("$addr/128", 6) or do {
			ETVPN::Logger::log("WARNING: ignoring invalid static IPv6 address '$addr'");
			return undef;
		};
		$ret->[0] = $ip;
	}
	if (defined($ifid)) {
		if ($ifid !~ /^::/) {
			$ifid = "::$ifid";
		}
		my $ip = new Net::IP("$ifid/128", 6) or do {
			ETVPN::Logger::log("WARNING: ignoring static IPv6 address due to invalid interface id '$ifid'");
			return undef;
		};
		$ret->[1] = $ip;
	}
	return $ret;
}


sub is_in_group {
	# not supposed to be executed on base class
	# need to be overrided if subclasses make use of helper method get_static_routes
	# when overriding, it should accept $obj->is_in_group($group, $backend_specific_optional_data) and return a boolean
	ETVPN::Logger::fatal("internal error: backend base class is_in_group() called");
}


sub get_ip_opt_val {
	# not supposed to be executed on base class
	# need to be overrided if subclasses make use of helper methods get_static_routes and get_static_ip
	# when overriding, it should accept $obj->get_conf_opt_val($ipver, $type, $backend_specific_optional_data) and return the stored value on the backend corresponding to the mentioned IP static or route option
	# $ipver can be undef, should the backend have a "mixed" IPv4 and IPv6 pushed routes option
	# $type can be 'addr' or 'routes'
	# return value should be:
	# - undef if not defined or respective configure options are not set
	# - a scalar with the address, without any /prefix_len, if type is 'addr' and ipver is 4
	# - an array ref with [ip_prefix, interface_id], without any /prefix_len, where one of them can be undef if not applicable, if type is 'addr' and ipver is 6
	# - an array ref if type is 'routes'
	ETVPN::Logger::fatal("internal error: backend base class get_ip_opt_val() called");
}


sub need_admin_credentials {
	# this is used by the cli tools, related to "need admin credentials" config option used by at least the SQL backend
	# here on the base class the default is true but this can be overridden by subclasses where the option actually exists
	return 1;
}


sub connect_as {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->connect_as($backend_username, $backend_password) and return a boolean
	ETVPN::Logger::fatal("internal error: backend base class connect_as() called");
}


sub disconnect {
	# can be overridden by subclasses
}


sub check_user_password {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->check_user_password($user_name, $realm, $user_password) and return a ETVPN::Login object reference, or undef on authentication failure (always setting the motive as a object error)
	ETVPN::Logger::fatal("internal error: backend base class check_user_password() called");
}


sub get_user_login_object {
	# not supposed to be executed on base class
	# not meant to be used for authentication purposes, but for tools that generate and store MFA challenges
	# when overriding, it should accept $obj->get_user_login($user_name, $realm, $extended) and return a ETVPN::Login object reference, or undef if the user does not exist or on error (always setting the motive as a object error)
	# $extended flag usage is optional for optimization, e.g. when it's possible to not retrieve unnecessary date
	ETVPN::Logger::fatal("internal error: backend base class get_user_login() called");
}


sub get_user_login {
	my ($self, $user_name, $realm, $extended) = @_;
	my $login = $self->get_user_login_object($user_name, $realm, $extended);
	$login->set_realm($realm) if defined($login);
	return $login;
}


sub update_user_secret {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->update_user_secret($secret_encoder, $secret_type, $user_name, $realm, $plain_secret) and return a boolean
	ETVPN::Logger::fatal("internal error: backend base class update_user_secret() called");
}


1;
