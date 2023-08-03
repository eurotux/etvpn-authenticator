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
use POSIX qw(strftime);
use IO::Interactive qw(is_interactive);
use File::Basename;
use MIME::Base64;
use Bytes::Random::Secure qw(random_bytes_base64);
use IO::Socket qw(AF_INET AF_UNIX);
use IO::Select;
use Net::IP;

use ETVPN::Logger;
use ETVPN::Conf;
use ETVPN::Login;
use ETVPN::Secret;
use ETVPN::Challenge;
use ETVPN::Util;


#################################
### Globals
#################################
$|=1;
my $need_help = 0;
my $default_ini_file = '/etc/etvpn/etux-vpnserver.ini';
my $config_file = $default_ini_file;
my $conf;
my $select = IO::Select->new();
my $mgmt_h;
my $ovpn_pid;
my $notify_h;
my @notify_sock_opts = (
	Listen    => 256,
	LocalAddr => '127.0.0.1',
	Proto     => 'tcp',
	Reuse     => 1,
);
my $sess_timeout;
my $user_login;
my $remote_ip = '(not connected)';
my $client;
my $client_reading = 0;
my $client_ready = 0;
my $client_event_type;
my $CLIENT_CONNECT = 1;
my $CLIENT_REAUTH = 2;
my $CLIENT_DISCONNECT = 3;
my $CLIENT_CR_RESPONSE = 4;
my %client_events = (
	$CLIENT_CONNECT => 'connect',
	$CLIENT_REAUTH => 'reauth',
	$CLIENT_DISCONNECT => 'disconnect',
	$CLIENT_CR_RESPONSE => 'cr_response',
);
my %mgmt_clients;
my %challenge_sessions;
my %verified_sids;
my %internal_error = (
	'IPPOOL' => 0,
	'BACKEND' => 0,
	'SECRET DECODING' => 0,
	'CHALLENGE' => 0,
);


#################################
### Subs
#################################
sub help {
	print "Usage:\n";
	print "\t$0 [... options ...]\n";
	print "\n";
	print "Options:\n";
	print "\t-c|--config-file=FILE     Provide alternate configuration file. Default is $default_ini_file\n";
	print "\t-h|--help                 Show this help message.\n";
	print "\n";
	exit 99;
}

sub decode_password_data($) {
	my ($password_data) = @_;
	my ($user_password, $session_id, $user_challenge_reply);
	# password line can have a cleartext password, or if it has a certain format it can have a base64 encoded password and challenge response
	my ($ep1, $ep2);
	if ( ( ($ep1, $ep2) = $password_data =~ /^CRV1::([^:]+)::(.*)/ ) ) {
		# Dynamic challenge with session string and challenge response
		# Format: CRV1::STRING_WITH_SESSION_ID::OTP code response provided by user/client
		$session_id = $ep1;
		$user_challenge_reply = $ep2;
	}
	elsif ( ( ($ep1, $ep2) = $password_data =~ /^SCRV1:([^:]+):(.*)/) ) {
		# Static challenge with challenge response
		# Format: SCRV1:<password_base64>:<response_base64>
		$user_password = decode_base64($ep1);
		$user_challenge_reply = decode_base64($ep2);
	}
	else {
		# Normal user authentication
		$user_password = $password_data;
	}
	return ($user_password, $session_id, $user_challenge_reply);
}

# check_challenge possible results
my $CHALLENGE_SUCCESS = 0;
my $CHALLENGE_FAILURE = 1;
my $CHALLENGE_NOT_PROVIDED = 2;
my $CHALLENGE_PENDING = 3;
my $CHALLENGE_NOT_CONFIGURED_FOR_USER = 4;
my $CHALLENGE_INTEGRITY_FAILURE = 5;
my $CHALLENGE_TYPE_UNKNOWN = 253;
my $CHALLENGE_INTERNAL_ERROR = 254;
sub check_challenge($$) {
	my ($login, $user_challenge_reply) = @_;

	return $CHALLENGE_NOT_CONFIGURED_FOR_USER unless $login->has_challenge_secret();

	# decrypt and validate challenge secret
	my $secret_decoder = ETVPN::Secret::new_from_conf($conf) or return $CHALLENGE_INTERNAL_ERROR;
	my $decode_result = $secret_decoder->decode($login);
	my $is_secret_internal_error = $secret_decoder->has_internal_error();
	$internal_error{'SECRET DECODING'} = $is_secret_internal_error;
	unless ($decode_result) {
		ETVPN::Logger::log($secret_decoder->get_errors());
		return $is_secret_internal_error ? $CHALLENGE_INTERNAL_ERROR : $CHALLENGE_INTEGRITY_FAILURE;
	};
	my ($type, $secret) = @$decode_result;

	# - if login object contains has a challenge object, then we're at the second phase of the CR protocol
	# reuse that object since it can contain internal data relevant to the second phase of the validation
	# - if not, then we're at the initial phase, thus create a new challenge object according to type stored
	# along secret data
	my $challenge = $login->get_associated_challenge();
	unless (defined($challenge)) {
		# create new challenge object according to type stored along secret data
		$challenge = ETVPN::Challenge::new_from_type($conf, $type) or return $CHALLENGE_TYPE_UNKNOWN;
		$login->set_associated_challenge($challenge);
	}

	# check if challenge requires pending authentication (as per openvpn management protocol client-pending-auth)
	# but support those challenges in "compatibility" mode for simpler clients by falling back to CR protocol when needed
	my $is_pending_type = $login->is_pending_auth() && !$challenge->is_crv($login);

	if ( !$is_pending_type &&
	     ( !defined($user_challenge_reply) ||
	       ( !$challenge->is_crv_allowed_empty_reply($login) && $user_challenge_reply eq '' ) ) ) {
		if ($challenge->is_crv($login)) {
			$challenge->set_secret($login, $secret);
		}
		# this result can be used to fail with a special reason (as per openvpn challenge-response protocol)
		# as long as $challenge->get_crv_prompt($login) returns a defined prompt
		return $CHALLENGE_NOT_PROVIDED;
	}

	# perform challenge validation
	my $challenge_validation = $challenge->validate($login, $secret, $user_challenge_reply);
	my $is_challenge_internal_error = $challenge->has_internal_error();
	$internal_error{'CHALLENGE'} = $is_challenge_internal_error;
	ETVPN::Logger::log($challenge->get_errors());
	if ($challenge_validation) {
		return $CHALLENGE_SUCCESS;
	}

	if ($is_pending_type) {
		return $CHALLENGE_PENDING;
	}

	# distinguish failure due to internal error
	if ($is_challenge_internal_error) {
		return $CHALLENGE_INTERNAL_ERROR;
	}

	return $CHALLENGE_FAILURE;
}

sub clear_session_id($$) {
	my ($u, $sid) = @_;

	if (defined($u) && defined($sid) && exists($challenge_sessions{$u})) {
		if (defined($challenge_sessions{$u}{$sid})) {
			# ensure any challenge object on the login object is unreferenced and destroyed first
			# so that when its destructor is invoked any log prefix is still valid
			$challenge_sessions{$u}{$sid}->[0]->set_associated_challenge(undef);
		}
		# delete the session
		delete $challenge_sessions{$u}{$sid};
		if (ref($challenge_sessions{$u}) ne 'HASH' || keys %{$challenge_sessions{$u}} == 0) {
			# no more sessions in memory for this user, so also clear that parent entry
			delete $challenge_sessions{$u};
		}
	}
}

sub clear_verified_sid($$) {
	my ($u, $sid) = @_;

	if (defined($u) && defined($sid) && exists($verified_sids{$u})) {
		delete $verified_sids{$u}{$sid};
		if (ref($verified_sids{$u}) ne 'HASH' || keys %{$verified_sids{$u}} == 0) {
			# no more verified sids for this user, so also clear that parent entry
			delete $verified_sids{$u};
		}
	}
}

sub gen_unique_session_key() {
	my $key;
	do {
		$key = random_bytes_base64(20, q{});
	} while (exists($challenge_sessions{$user_login}{$key}) || exists($verified_sids{$user_login}{$key}));
	return $key;
}

sub auth_user_pass_verify() {
	my $password_data;
	if (!defined($client->{'env'}->{'password'}) || ( $password_data = $client->{'env'}->{'password'} ) eq '') {
		ETVPN::Logger::log("login failed: invalid login attempt (no password data provided)");
		return undef;
	}

	my ($user_password, $session_id, $user_challenge_reply) = decode_password_data($password_data);
	my $login;
	my $session;
	if (defined($user_password)) {
		ETVPN::Logger::log("new authentication attempt");
		my $backend_realm = $conf->get_username_backend_realm($user_login) or do {
			ETVPN::Logger::log("login failed: unknown realm");
			return undef;
		};
		my ($backend, $user_name, $realm) = @$backend_realm;
		ETVPN::Logger::log("validating on realm $realm");
		$login = $backend->validate_login($user_name, $realm , $user_password);
		my $is_backend_internal_error = $backend->has_internal_error();
		$internal_error{'BACKEND'} = $is_backend_internal_error;
		unless ($login && $login->is_success()) {
			# ensure 'login failed: ' is only present on non internal error so that a logged bannable error is distinguishable
			if ($is_backend_internal_error) {
				ETVPN::Logger::log($backend->get_errors());
				ETVPN::Logger::log('rejecting login due to authentication backend internal error');
			}
			else {
				# note: use get_error() and not get_errors() here on purpose so that a login failure is on a single line
				# prepended by the bannable prefix
				my $motive_log = $backend->get_error();
				$motive_log = 'backend validation failed' unless $motive_log;
				ETVPN::Logger::log("login failed: $motive_log");
			}
			return undef;
		}
		# store safe environment on login object
		delete($client->{'env'}->{'password'});
		$login->set_env($client->{'env'});
	}
	elsif (defined($session_id)) {
		unless (exists($challenge_sessions{$user_login}{$session_id})) {
			# bannable error
			ETVPN::Logger::log('login failed: attempt to resume an invalid or expired dynamic CR session');
			return undef;
		}
		$session = $challenge_sessions{$user_login}{$session_id};
		$login = $session->[0];
		ETVPN::Logger::log('resuming existing CR authentication session from cid '.$login->get_cid_kid()->[0]);
		if ( !$session->[0]->is_pending_auth() &&
		     (!defined($user_challenge_reply) || !$user_challenge_reply ne '') ) {
			# bannable error
			ETVPN::Logger::log('login failed: user tried to send empty challenge response');
			clear_session_id($user_login, $session_id);
			return undef;
		}
		if ($remote_ip ne $session->[4]) {
			# bannable error
			ETVPN::Logger::log('login failed: challenge reply came from different IP address (session was originally sent to address '.$session->[4].')');
			clear_session_id($user_login, $session_id);
			return undef;
		}
	}
	else {
		# bannable error TODO: test this thoroughly
		ETVPN::Logger::log('login failed: invalid attempt');
		return undef;
	}

	# validate challenge
	# TODO: add account lock by challenge?
	my $challenge_result = check_challenge($login, $user_challenge_reply);
	# proceed according to validation result
	if ($challenge_result == $CHALLENGE_SUCCESS ||
	    ($challenge_result == $CHALLENGE_NOT_CONFIGURED_FOR_USER && !$conf->val('enforce mfa'))) {
		# log successful attempt
		ETVPN::Logger::log('login successful');
		clear_session_id($user_login, $session_id);
		return $login;
	}

	my $attempt = 1;
	my $auth_extra;
	if ($challenge_result == $CHALLENGE_FAILURE ||
	    $challenge_result == $CHALLENGE_NOT_PROVIDED ||
	    $challenge_result == $CHALLENGE_PENDING) {
		if (defined($session)) {
			$attempt = ++$session->[2];
			if ($attempt >= 3) {
				# bannable error
				ETVPN::Logger::log('login failed: too many failed challenge attempts');
				clear_session_id($user_login, $session_id);
				return undef;
			}
			$auth_extra = $session->[3];
		}
		else {
			$session_id = gen_unique_session_key();
			# the user login, which we use to index the auth sessions, in some cases may not be the same as the account name
			# because of that, store the user login so that challenges can pass necessary information for
			# later notification
			$login->set_auth_data($user_login, $session_id);
			$login->set_cid_kid($client->{'cid'}, $client->{'kid'});
			my $challenge = $login->get_associated_challenge();
			my ($crv_prompt, $can_echo) = $challenge->get_crv_prompt($login);
			if (defined($crv_prompt)) {
				$auth_extra = 'CRV1:R'.($can_echo ? ',E' : '').":$session_id:".encode_base64($user_login, q{}).":$crv_prompt";
			}
			$challenge_sessions{$user_login}{$session_id} = [$login, time, 0, $auth_extra, $remote_ip];
		}
	}

	if ($challenge_result == $CHALLENGE_FAILURE) {
		$client->{'fail_motive'} = $auth_extra;
		# bannable error
		ETVPN::Logger::log("login failed: challenge verification failed (attempt $attempt)");
	}
	elsif ($challenge_result == $CHALLENGE_NOT_PROVIDED) {
		if ($attempt > 1) {
			# bannable error
			ETVPN::Logger::log('login failed: challenge request was ignored by remote client');
		}
		else {
			$client->{'fail_motive'} = $auth_extra;
			ETVPN::Logger::log('sent dynamic CR challenge information');
		}
	}
	elsif ($challenge_result == $CHALLENGE_PENDING) {
		my $challenge = $login->get_associated_challenge();
		if ( ( $client->{'pending_auth'} = $challenge->get_pending_string($login) ) ) {
			$client->{'pending_auth_sid'} = $session_id;
			ETVPN::Logger::log('login pending external authorization');
		}
		else {
			ETVPN::Logger::log('error associating pending external authorization');
		}
	}
	elsif ($challenge_result == $CHALLENGE_NOT_CONFIGURED_FOR_USER) {
		ETVPN::Logger::log('challenge not configured for user, PLEASE REVIEW THIS USER CONFIGURATION');
	}
	elsif ($challenge_result == $CHALLENGE_INTEGRITY_FAILURE) {
		ETVPN::Logger::log('configured challenge for user failed integrity check, PLEASE REVIEW THIS USER CONFIGURATION');
	}
	elsif ($challenge_result == $CHALLENGE_TYPE_UNKNOWN) {
		ETVPN::Logger::log('unknown challenge type, please review the user configuration');
	}
	else {
		ETVPN::Logger::log('internal error verifying challenge');
	}

	return undef;
}

sub listen_for_notify_requests() {
	$notify_h = IO::Socket::INET->new(@notify_sock_opts, LocalPort => $conf->val('notify port'))
		or ETVPN::Logger::fatal_code(4, "error listening for notify requests: $!");
	$select->add($notify_h);
}

sub connect_to_management_interface() {
	my $fully_connected = 0;
	my $connect_to_wait = $conf->val('management interface connect timeout');
	my $connect_ts;
	my $to_sleep = 0;
	my $sleep_ts;
	my $new_pid;
	new_client();
	do {
		# Retry connection until successfully authenticated
		# However connecting and reading can be interrupted by SIGHUP if configuration is reloaded
		# so we have to deal with that
		eval {
			while (1) {
				if ($to_sleep >= 0) {
					$sleep_ts = time;
					sleep($to_sleep);
				}
				$sleep_ts = undef;
				ETVPN::Logger::log("connecting to OpenVPN management interface...") unless defined($connect_ts);
				$connect_to_wait = 1 if $connect_to_wait <= 1;
				$connect_ts = time;
				$mgmt_h = IO::Socket::INET->new(
					PeerAddr => $conf->val('management interface address'),
					PeerPort => $conf->val('management interface port'),
					Proto    => 'tcp',
					Type     => IO::Socket::SOCK_STREAM,
					Timeout => $connect_to_wait
				);
				$connect_ts = undef;
				$connect_to_wait = $conf->val('management interface connect timeout');
				if (defined($mgmt_h)) {
					# Send password
					ETVPN::Logger::log("connected to OpenVPN management interface");
					my $line;
					local $/ = ':';
					$line = $mgmt_h->getline();
					if (!defined($line)) {
						ETVPN::Logger::log('OpenVPN management interface connection was closed before authentication could be attempted');
					}
					elsif ($line =~ /PASSWORD:$/) {
						print $mgmt_h $conf->val('management interface password')."\r\npid\r\n";
						$line = $mgmt_h->getline();
						if (!defined($line)) {
							ETVPN::Logger::log('OpenVPN management interface connection was closed while performing authentication');
						}
						elsif ($line =~ /^SUCCESS:/) {
							ETVPN::Logger::log('authenticated to OpenVPN management interface');
							# read and discard rest of success message, e.g. "password is correct"
							local $/ = "\r\n";
							$mgmt_h->getline();
							# read and discard eventual INFO message(s)
							do {
								$line = $mgmt_h->getline();
							} while (defined($line) && $line =~ /^>INFO:/);
							# check for PID on the response
							if (!defined($line)) {
								ETVPN::Logger::log('OpenVPN management interface connection was closed while retrieving instance PID');
							}
							elsif ($line =~ /^SUCCESS:\s*pid=(\d+)/) {
								$new_pid = $1;
								$mgmt_h->blocking(0);
								$select->add($mgmt_h);
								$fully_connected = 1;
								last;
							}
							else {
								ETVPN::Logger::log('connection failure or management protocol error: unable to obtain OpenVPN instance PID');
							}
						}
						else {
							ETVPN::Logger::log("can't connect to OpenVPN management interface: authentication failure (PLEASE CORRECT THE PASSWORD IN THE CONFIGURATION)");
						}
					}
					else {
						ETVPN::Logger::log("can't connect to OpenVPN management interface: did not receive a password prompt (please ensure you specify a password in OpenVPN \"management\" option)");
					}
					$mgmt_h->close();
				}
				else {
					ETVPN::Logger::log("error connecting to OpenVPN management interface: $!");
				}
				ETVPN::Logger::log('could not connect to OpenVPN management interface, retrying in '.$conf->val('management interface retry').' seconds');
				$to_sleep = $conf->val('management interface retry');
			};
		};
		if ($@) {
			if ($@ eq "reload\n") {
				# reload signal caught while still connecting
				reload();
				if (defined($connect_ts)) {
					if (( $connect_to_wait -= time - $connect_ts ) <= 0) {
						$connect_to_wait = $conf->val('management interface connect timeout');
					}
				}
				elsif (defined($sleep_ts) && ( $to_sleep -= time - $sleep_ts ) <= 0) {
					$to_sleep = $conf->val('management interface retry');
				}
			}
			else {
				# propagate other errors/signals
				die $@;
			}
		}
	} while (!$fully_connected);
	return $new_pid;
}

sub reconnect_to_management_interface() {
	$select->remove($mgmt_h) if defined($mgmt_h);
	# temporarily close notify port, openvpn is down so we must refuse any attempts
	$select->remove($notify_h);
	$notify_h->close();
	# close any other active connection
	foreach my $h ($select->handles) {
		$h->close();
	}
	# recreate select object
	$select = IO::Select->new();
	my $new_pid;
	do {
		# ...and connect to management interface
		if (defined($mgmt_h)) {
			ETVPN::Logger::log('lost connection to openvpn management interface, reconnecting');
			$select->remove($mgmt_h) if $select->exists($mgmt_h);
			$mgmt_h->close();
			$mgmt_h = undef;
		}
		$new_pid = connect_to_management_interface();
	} while (!defined($new_pid));
	if (!defined($ovpn_pid) || $ovpn_pid != $new_pid) {
		# openvpn was restarted, so invalidate every session since client and key ids were reset
		ETVPN::Logger::log("OpenVPN instance was restarted, new PID is $new_pid");
		if (defined( my $ippool = $conf->val('ippool') )) {
			$ippool->register_ovpn_instance($conf->val('management interface address'), $conf->val('management interface port'), $new_pid);
		}
		%challenge_sessions = ();
		%verified_sids = ();
		%mgmt_clients = ();
		$ovpn_pid = $new_pid;
	}
	else {
		ETVPN::Logger::log("reconnected successfully to OpenVPN instance with PID $ovpn_pid");
	}
	# listen again for notifications
	listen_for_notify_requests();
}

sub ovpn_mgmt_quote($) {
	my ($s) = @_;
	$s =~ s/\\/\\\\/g;
	$s =~ s/"/\\"/g;
	return "\"$s\"";
}

sub new_client() {
	my $initializing = 1;
	do {
		# these values must *always* be set together even if we are spammed by reload requests
		eval {
			$user_login = undef;
			$client_reading = 0;
			$remote_ip = '(not connected)';
			$client_event_type = undef;
			$client = { env => {} };
			$client_ready = 0;
			$initializing = 0;
		};
		die $@ if $@ && $@ ne "reload\n";
	} while ($initializing);
}

sub clean_stale_sessions() {
	foreach my $u (keys %challenge_sessions) {
		my $user_sessions = $challenge_sessions{$u};
		foreach my $sid (keys %$user_sessions) {
			my $session = $user_sessions->{$sid};
			if (time - $session->[1] >= $conf->val('challenge session timeout')) {
				my $clear_login = $session->[0];
				# push prefix to logger class to associate it to messages of cleaned objects triggered by garbage collection
				# (note: should work, since perl supposedly destroys objects as soon as their reference count drops to zero,
				# but in reality the object destruction is delayed, at least as of perl 5.34)
				my $pend_cid_kid = $clear_login->get_cid_kid();
				ETVPN::Logger::push_prefix("user $u [".$session->[4].']'.($pend_cid_kid ? ' (cid '.$pend_cid_kid->[0].')' : '').': ');
				ETVPN::Logger::log(($clear_login->is_pending_auth() ? 'auth pending' : 'dynamic challenge reply') . ' session timed out');
				clear_session_id($u, $sid);
				ETVPN::Logger::pop_prefix();
			}
		}
	}
	$sess_timeout = $conf->val('challenge session timeout');
}

sub reload() {
	local $SIG{HUP} = 'IGNORE';
	ETVPN::Logger::log('reloading configuration...');
	$conf->reload($config_file);
	# since a reload can also interrupt, handle stale sessions if needed
	clean_stale_sessions();
	ETVPN::Logger::log('completed reloading configuration');
}

sub throw_reload {
	ETVPN::Logger::log("configuration reload requested");
	die "reload\n";
}

sub authorize_client($$$) {
	my ($cid, $kid, $auth_login) = @_;
	print $mgmt_h "client-auth $cid $kid\r\n";

	my ($user_login_name, $verified_sid) = $auth_login->get_auth_data();
	if (defined($verified_sid)) {
		# verified session exists, enable reauth support
		$mgmt_clients{$cid}->{'verified_sid'} = $verified_sid;
		$verified_sids{$user_login_name}{$verified_sid} = $cid;
	}

	my $l_env = $auth_login->get_env();

	my $ip4 = $auth_login->get_static_ip4();
	if (defined($ip4)) {
		my $push_ip4;
		if ($ip4->size() == 1) {
			$push_ip4 = $ip4;
		}
		else {
			if ( defined( my $ippool = $conf->get_ip_pool() )) {
				# get IP from pool but ensure the local server IP is not returned
				$push_ip4 = $ippool->get_user_pool_ip($ip4, $auth_login->get_account_name(), $auth_login->get_realm(), $cid, 4, $l_env->{'ifconfig_local'});
				if ( ( $internal_error{'IPPOOL'} = $ippool->has_internal_error() ) ) {
					ETVPN::Logger::log($ippool->get_errors());
				}
			}
			else {
				ETVPN::Logger::log("WARNING: ignoring dynamic IP since no ippool is configured");
			}
		}
		if (defined($push_ip4)) {
			# push IPv4 address
			my $addr = $push_ip4->ip();
			my $remote_mask;
			if (defined($l_env->{'ifconfig_remote'})) {
				# topology is net30 or p2p
				# do a best effort to find a "compatible" IP inside the same /30 network to circumvent the limitations of Windows clients' tun/tap driver
				# if it's not possible, just give the next IP in the network, should at least be good for non-Windows client
				# in any case, it's the responsibility of who manages the static IP list that they know which addresses they
				# can assign to be valid depending on the client, we can't do much more here
				my ($first_octs, $oct) = $addr =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})$/;
				if (defined($oct)) {
					# on a /30 network, when the last octect is congruent (mod 4) with:
					# 0 - network address
					# 1 - first host
					# 2 - last host
					# 3 - broadcast address
					$remote_mask = $first_octs.($oct % 4 >= 2 ? $oct-1 : $oct+1);
				}
				else {
					ETVPN::Logger::log("WARNING: ignoring invalid static IPv4 address $addr");
				}
			}
			else {
				# topology should be subnet
				$remote_mask = $l_env->{'ifconfig_netmask'};
				if (defined($remote_mask)) {
					print $mgmt_h "push \"topology subnet\"\r\n";
					# pushed route-gateway must be inside the same client subnet, so that they can set the routes
					# on their side
					# a bit of an hack, but this way even if the client IP isn't in the same network as the server,
					# the traffic always goes through the client TUN interface and arrives at the server side which
					# is what in fact matters (openvpn will then take care of the rest)
					# normally use the first IP on the subnet, but if it's the same as the client IP, then use the
					# next
					my $net_peer_ip = ETVPN::Util::net_peer_ip($addr, $remote_mask, 4);
					my $route_gateway = defined($net_peer_ip) ? $net_peer_ip : $l_env->{'ifconfig_local'};
					if (defined($route_gateway)) {
						print $mgmt_h "push \"route-gateway $route_gateway\"\r\n";
					}
				}
				else {
					# show warning if topology is not subnet as expected
					ETVPN::Logger::log('WARNING: ignoring setting static IPv4 address due to unknown topology');
				}
			}
			if (defined($remote_mask)) {
				print $mgmt_h "ifconfig-push $addr $remote_mask\r\n";
				print $mgmt_h "iroute $addr\r\n";
			}
		}
	}

	my $static_ip6 = $auth_login->get_static_ip6();
	if (defined($static_ip6)) {
		# push static IPv6
		my ($ip6_local, $ifconfig_ipv6_local, $ifconfig_ipv6_netbits);
		if ( !( defined( $ifconfig_ipv6_local = $l_env->{'ifconfig_ipv6_local'} ) &&
			   defined( $ifconfig_ipv6_netbits = $l_env->{'ifconfig_ipv6_netbits'} ) ) ) {
			ETVPN::Logger::log("WARNING: ignoring setting static IPv6 address since the OpenVPN server is not configured as such and probably missing server-ipv6 or ifconfig-ipv6 options");
		}
		elsif ( !(defined ( $ip6_local = new Net::IP("$ifconfig_ipv6_local/128", 6) )) ) {
			ETVPN::Logger::log("WARNING: ignoring setting static IPv6 address since the OpenVPN server reports invalid ifconfig_ipv6_local address '$ifconfig_ipv6_local'");
		}
		elsif ( ! ($ifconfig_ipv6_netbits >= 1 && $ifconfig_ipv6_netbits <= 128) ) {
			ETVPN::Logger::log("WARNING: ignoring setting static IPv6 address since the OpenVPN server reports invalid ifconfig_ipv6_netbits value ''$ifconfig_ipv6_netbits'");
		}
		else {
			if ( defined(my $ip = ETVPN::Util::ipv6_from_prefix_ifid_tuple($static_ip6, $ip6_local, $ifconfig_ipv6_netbits)) ) {
				my $addr = $ip->short()."/$ifconfig_ipv6_netbits";
				print $mgmt_h "ifconfig-ipv6-push $addr $ifconfig_ipv6_local\r\n";
				print $mgmt_h "iroute-ipv6 $addr\r\n";
			}
		}
	}

	# push ip routes
	foreach my $ip (@{$auth_login->get_full_push_routes_list()}) {
		my $ipver = $ip->version();
		if ($ipver == 4) {
			print $mgmt_h 'push "route '.$ip->ip().' '.$ip->mask()."\"\r\n";
		}
		elsif ($ipver == 6) {
			print $mgmt_h 'push "route-ipv6 '.$ip->short().'/'.$ip->prefixlen()."\"\r\n";
		}
		else {
			# should not occur, but if it does it's better to have it logged
			ETVPN::Logger::log('WARNING: ignoring an invalid IP object while pushing routes');
		}
	}

	print $mgmt_h "END\r\n";
}

sub deny_client($$;$) {
	my ($cid, $kid, $motive) = @_;

	my @deny_params = ($cid, $kid);
	if (defined($motive)) {
		push @deny_params, ovpn_mgmt_quote('ETUX VPN challenge'), ovpn_mgmt_quote($client->{'fail_motive'});
	}
	else {
		push @deny_params, ovpn_mgmt_quote('ETUX VPN authentication failed');
	}
	print $mgmt_h 'client-deny '.join(' ', @deny_params)."\r\n";
}

sub free_ippool_address($) {
	my $cid = shift;
	if (defined( my $ippool = $conf->get_ip_pool() )) {
		my $freed = $ippool->free_user_address($cid, 4);
		if ($freed < 0) {
			ETVPN::Logger::log($ippool->get_errors());
		}
		elsif ($freed) {
			ETVPN::Logger::log("freed $freed address".($freed == 1 ? '' : 'es').' from IP pool');
		}
		$internal_error{'IPPOOL'} = $ippool->has_internal_error();
	}
}

sub process_client_mgmt_event() {
	clean_stale_sessions();

	my $cid = $client->{'cid'};
	my $client_env = $client->{'env'};
	my $verified_sid;
	my $pending_auth_sid;
	if ( ( my $existing_client = $mgmt_clients{$cid} ) ) {
		# event related to a known client connection ID (cid)
		# merge what we already had but only do so if this event has something potentially new
		if (%$client_env) {
			$client_env = $existing_client->{'env'} = { %{$client->{'env'}}, %{$existing_client->{'env'}} };
		}
		else {
			$client_env = $existing_client->{'env'};
		}
		$verified_sid = $existing_client->{'verified_sid'};
		$client->{'pending_auth'} = $existing_client->{'pending_auth'};
		$pending_auth_sid = $existing_client->{'pending_auth_sid'};
	}

	$remote_ip = $client_env->{'untrusted_ip'} || $client_env->{'trusted_ip'} || 'could not determine remote ip';
	if (!defined($client_env->{'username'}) || ( $user_login = $client_env->{'username'} ) eq '') {
		ETVPN::Logger::log("[$remote_ip] (cid $cid): ignored unknown client ".$client_events{$client_event_type}.' event');
		delete($mgmt_clients{$cid});
		free_ippool_address($cid);
	}
	else {
		# cleanup flag - will be set to true on certain conditions below so that data no longer needed is properly
		# cleared/freed at the end of this sub
		my $cleanup = 0;

		# add logging prefix related to this client event but ensure level is always restored
		my $restore_prefix_level = ETVPN::Logger::current_level();
		# ensure logging format with remote address so additional measures such as fail2ban can be implemented
		ETVPN::Logger::push_prefix("user $user_login [$remote_ip] (cid $cid): ");

		if ($client_event_type == $CLIENT_CONNECT) {
			my $kid = $client->{'kid'};
			ETVPN::Logger::log("client connect with key id $kid");
			$mgmt_clients{$cid} = $client;
			my $verified_login = auth_user_pass_verify();

			if ($verified_login) {
				authorize_client($cid, $kid, $verified_login);
			}
			else {
				if (defined($client->{'pending_auth'})) {
					# TODO maybe someday use a parameter for the timeout sent in the following line (when openurl)
					print $mgmt_h "client-pending-auth $cid ".$client->{'pending_auth'}."\r\n";
				}
				else {
					# fail motive can be a CR challenge
					deny_client($cid, $kid, $client->{'fail_motive'});
				}
			}
		}
		elsif ($client_event_type == $CLIENT_REAUTH) {
			my $kid = $client->{'kid'};
			ETVPN::Logger::log("client reauth requested with key id $kid");
			my $reauth_ok = 0;
			my $password_data;
			unless ($verified_sid) {
				ETVPN::Logger::log("denied reauth attempt (no verified auth session for matching client)");
			}
			elsif (!defined($client->{'env'}->{'password'}) || ( $password_data = $client->{'env'}->{'password'} ) eq '') {
				ETVPN::Logger::log("denied reauth attempt (no password data provided)");
			}
			else {
				my $client_auth_sid = (decode_password_data($password_data))[1];
				if ( defined($client_auth_sid) &&
				     $client_auth_sid eq $verified_sid &&
				     exists($verified_sids{$user_login}{$client_auth_sid}) &&
				     $verified_sids{$user_login}{$client_auth_sid} eq $cid ) {
					$reauth_ok = 1;
					ETVPN::Logger::log("client reauth successfull");
					print $mgmt_h "client-auth-nt $cid $kid\r\n";
				}
				else {
					ETVPN::Logger::log("denied reauth attempt (mismatched auth session)");
				}
			}
			unless ($reauth_ok) {
				deny_client($cid, $kid);
				$cleanup = 1;
			}
		}
		elsif ($client_event_type == $CLIENT_CR_RESPONSE) {
			my $kid = $client->{'kid'};
			my $login_success;
			my $fail_motive;
			my $pend_session;
			my $r;
			# when validating a CR RESPONSE, unlike the other client event types, we assume by default it will
			# fail and thus a cleanup will be needed at the end of this sub; in case of sucess, the cleanup flag
			# is reset to 0 below
			$cleanup = 1;
			if (!defined($pending_auth_sid) || !defined( $pend_session = $challenge_sessions{$user_login}{$pending_auth_sid})) {
				$fail_motive = 'CR RESPONSE related pending auth session not found or already expired';
			}
			elsif ( defined( $r = $client->{'cr_response'} ) &&
				defined( my $user_response = decode_base64($r) ) ) {
				my $pend_challenge;
				# session format: [$login, time, retries, $auth_extra, $remote_ip]
				my $pend_login = $pend_session->[0];
				if (!$pend_login) {
					$fail_motive = 'CR RESPONSE related pending login data not found';
				}
				elsif ( !($pend_challenge = $pend_login->get_associated_challenge()) ) {
					$fail_motive = 'CR RESPONSE related pending challenge data not found';
				}
				else {
					my $validate_result = $pend_challenge->validate_pending_auth($pend_login, $user_response);
					if ($validate_result) {
						# log successful pending login attempt
						ETVPN::Logger::log("pending login successful (CRTEXT challenge)");
						authorize_client($cid, $kid, $pend_login);
						$login_success = 1;
					}
					else {
						# ensure 'login failed: ' is only present on non internal error so that a logged bannable error is distinguishable
						my $is_pend_challenge_internal_error = $pend_challenge->has_internal_error();
						$internal_error{'CHALLENGE'} = $is_pend_challenge_internal_error;
						if ($is_pend_challenge_internal_error) {
							$fail_motive = $pend_challenge->get_errors();
						}
						else {
							my $attempt = ++$pend_session->[2];
							# note: use get_error() and not get_errors() here on purpose so that a login failure is on a single line
							my $challenge_motive = $pend_challenge->get_error();
							ETVPN::Logger::log('login failed: '.($challenge_motive ? $challenge_motive : 'incorrect CRTEXT challenge response')." (attempt $attempt)");
							if ($attempt >= 3) {
								$fail_motive = 'too many failed CRTEXT challenge attempts';
							}
							else {
								print $mgmt_h "client-pending-auth $cid ".$client->{'pending_auth'}."\r\n";
								# CR sucesss, reset the cleanup flag to 0
								$cleanup = 0;
							}
						}
					}
				}
			}
			else {
				$fail_motive = 'invalid base64 cr_response';
			}
			if (!$login_success && $fail_motive) {
				ETVPN::Logger::log($fail_motive ? $fail_motive : 'could not validate CRTEXT challenge');
				deny_client($cid, $kid);
			}
		}
		elsif ($client_event_type == $CLIENT_DISCONNECT) {
			ETVPN::Logger::log("client disconnect");
			# $pending_auth_sid is only defined if the related challenge is of pending_auth type
			# for CRV type challenges it will be undefined so any related session will still persist
			$cleanup = 1;
		}
		else {
			ETVPN::Logger::log("WARNING: unknown event type $client_event_type - this should not happen, please report a issue on https://github.com/eurotux/etvpn-authenticator");
			$cleanup = 1;
		}

		if ($cleanup) {
			delete($mgmt_clients{$cid});
			foreach my $clean_sid ($pending_auth_sid, $verified_sid) {
				if (defined($clean_sid)) {
					clear_session_id($user_login, $clean_sid);
					clear_verified_sid($user_login, $clean_sid);
				}
			}
			free_ippool_address($cid);
		}

		ETVPN::Logger::pop_prefix({'level' => $restore_prefix_level});
	}

	# ensure client info is cleared and prepared for next
	new_client();
}

sub process_mgmt_line_check_ready($) {
	$_ = shift;
	if (/^ERROR(?::\s*)?(.+)/) {
		ETVPN::Logger::log("WARNING: got management interface error: $1");
		new_client();
	}
	elsif ($client_reading) {
		if (/^>CLIENT:(.+)/) {
			my ($type, $options) = split(/,/, $1, 2) or die "next\n";
			if ($type eq 'ENV') {
				if ($options eq 'END') {
					$client_reading = 0;
					# client is ready for processing
					return 1;
				}
				else {
					my ($var, $val) = split(/=/, $options, 2) or die "next\n";
					$client->{'env'}{$var} = $val;
				}
			}
		}
	}
	elsif (/^>CLIENT:CONNECT,(\d+),(\d+)/) {
		$client->{'cid'} = $1;
		$client->{'kid'} = $2;
		$client_event_type = $CLIENT_CONNECT;
		$client_reading = 1;
	}
	elsif (/^>CLIENT:REAUTH,(\d+),(\d+)/) {
		$client->{'cid'} = $1;
		$client->{'kid'} = $2;
		$client_event_type = $CLIENT_REAUTH;
		$client_reading = 1;
	}
	elsif (/^>CLIENT:DISCONNECT,(\d+)/) {
		$client->{'cid'} = $1;
		$client_event_type = $CLIENT_DISCONNECT;
		$client_reading = 1;
	}
	elsif (/^>CLIENT:CR_RESPONSE,(\d+),(\d+),(.*)/) {
		$client->{'cid'} = $1;
		$client->{'kid'} = $2;
		$client->{'cr_response'} = $3;
		$client_event_type = $CLIENT_CR_RESPONSE;
		$client_reading = 1;
	}
	# need to read more data for client
	return 0;
}

sub process_pending_notify($$$) {
	my ($pend_user_login, $pend_remote_ip, $pend_sid) = @_;
	unless (exists($challenge_sessions{$pend_user_login}{$pend_sid})) {
		ETVPN::Logger::log("attempt to notify about a non-existing, expired or unrelated session");
		return "NOTFOUND";
	}
	my $pend_session = $challenge_sessions{$pend_user_login}{$pend_sid};
	# session format: [$login, time, retries, $auth_extra, $remote_ip]
	if ( (my $pend_login = $pend_session->[0]) && (my $pend_expected_remote_ip = $pend_session->[4]) ) {
		if ($pend_remote_ip ne $pend_expected_remote_ip) {
			ETVPN::Logger::log("attempt to perform pending authentication from mismatched address $pend_remote_ip (expected: $pend_expected_remote_ip)");
			return "DENIED Source IP mismatch";
		}
		my $pend_challenge = $pend_login->get_associated_challenge() or do {
			ETVPN::Logger::log("attempt to notify about a non-pending auth session");
			return "NOTFOUND";
		};
		my $is_crv = $pend_challenge->is_crv($pend_login);
		my $pend_cid_kid = $pend_login->get_cid_kid();
		unless (defined($pend_cid_kid)) {
			ETVPN::Logger::log('unable to find related CID and KID while processing pending '.($is_crv ? 'CR validation' : 'auth').' session');
			return "NOTFOUND";
		}
		my ($cid, $kid) = @$pend_cid_kid;
		my $validate_result = $pend_challenge->validate_pending_auth($pend_login);
		# TODO: set retriable possibility in base challenge class and auth daemon code for pending auths
		my $reply;
		if ($validate_result) {
			if ($is_crv) {
				# this is a notified challenge in CR "compatibility" mode
				# log successful pending CR login validation, keep session in memory until client tries
				# to reconnect with same auth session ID from same IP address
				ETVPN::Logger::log("pending CR validation related to cid $cid successful");
			}
			else {
				# client pending auth protocol
				# log successful pending login attempt
				ETVPN::Logger::log("pending cid $cid login successful");
				authorize_client($cid, $kid, $pend_login);
				clear_session_id($pend_user_login, $pend_sid);
			}
			$reply = "OK";
		}
		else {
			unless ($is_crv) {
				# client pending auth protocol, deny access to the client that is connected and waiting
				deny_client($cid, $kid);
			}
			# ensure 'login failed: ' is only present on non internal error so that a logged bannable error is distinguishable
			my $is_pend_challenge_internal_error = $pend_challenge->has_internal_error();
			$internal_error{'CHALLENGE'} = $is_pend_challenge_internal_error;
			if ($is_pend_challenge_internal_error) {
				ETVPN::Logger::push_prefix("(cid $cid) ") unless $is_crv;
				ETVPN::Logger::log($pend_challenge->get_errors());
				ETVPN::Logger::pop_prefix() unless $is_crv;
			}
			else {
				# note: use get_error() and not get_errors() here on purpose so that a login failure is on a single line
				# prepended by the bannable prefix
				my $challenge_motive = $pend_challenge->get_error();
				ETVPN::Logger::log($challenge_motive) if $challenge_motive;
				ETVPN::Logger::log("login failed: pending".($is_crv ? " original cid $cid" : " cid $cid").' validation failure');
			}
			clear_session_id($pend_user_login, $pend_sid);
			$reply = "DENIED";
		}
		return $reply;
	}
	# should not happen
	ETVPN::Logger::log("unexpected error in process_pending_notify");
	return "ERROR";
}


#######################################
### Main
#######################################

# Don't die prematurely
$SIG{HUP} = 'IGNORE';

# Command line
GetOptions (
	'h|help' => \$need_help,
	'c|config-file=s' => \$config_file,
) or do {
	print "Invalid parameters.\n\n";
	$need_help = 1;
};
help if $need_help || @ARGV;

# Load configuration (dies on error)
$conf = ETVPN::Conf->new($config_file);

# Show an extra prefix when running in terminal
# Not needed if running as a service
if (is_interactive()) {
	ETVPN::Logger::push_prefix(sub { strftime('%Y-%m-%d %H:%M:%S %z', localtime) }, ' '.basename($0, '.pl').": ");
}

my $sess_cleanup_ts;
$sess_timeout = $conf->val('challenge session timeout');

$SIG{USR1} = \&throw_reload;
$ovpn_pid = connect_to_management_interface();
ETVPN::Logger::log("OpenVPN instance PID is $ovpn_pid");
if (defined( my $ippool = $conf->get_ip_pool() )) {
	$ippool->register_ovpn_instance($conf->val('management interface address'), $conf->val('management interface port'), $ovpn_pid);
}
listen_for_notify_requests();

my $mgmt_prev = '';
my $mgmt_buf;
while (1) {
	# some modules mess up the signal handling, ensure it's restored on each iteration
	$SIG{HUP} = \&throw_reload;

	# exception catching, for handling reloads safely
	# (management interface reconnection sub has its own handling)
	eval {
		$sess_cleanup_ts = time;
		$! = 0;
		my @ready = $select->can_read($sess_timeout >= 0 ? $sess_timeout : 1);
		unless (@ready) {
			if ($!) {
				ETVPN::Logger::log("IO::Select error: $!");
			}
			else {
				# timeout reached
				clean_stale_sessions();
			}
			die "next\n";
		}
		if ( ($sess_timeout -= time - $sess_cleanup_ts) <= 0) {
			clean_stale_sessions();
		}
		foreach my $h (@ready) {
			if ($h == $mgmt_h) {
				# got data from the management interface
				# we can't use $socket->getline since we're using IO::Select
				my $rbytes;
				my @lines;
				while ( ($rbytes = sysread $mgmt_h, $mgmt_buf, 256) ) {
					push @lines, split(/\r\n/, $mgmt_prev.$mgmt_buf, -1);
					$mgmt_prev = pop @lines;
				}
				if (defined($rbytes)) {
					# rbytes is defined, meaning it returned 0 (eof), so OpenVPN was restarted
					reconnect_to_management_interface();
					die "next\n";
				}
				foreach my $line (@lines) {
					if (process_mgmt_line_check_ready($line)) {
						process_client_mgmt_event();
					}
				}
			}
			elsif ($h == $notify_h) {
				# new notify connection (from CGI)
				my $new = $notify_h->accept();
				if (defined($new)) {
					$new->blocking(0);
					$select->add($new);
				}
				else {
					ETVPN::Logger::log("error accepting notify connection: $!");
				}
			}
			else {
				# process notify connection request
				$select->remove($h);
				my $notify_address = $h->peerhost().':'.$h->peerport();
				my $notify_buf;
				my $rbytes = sysread $h, $notify_buf, 256;
				my ($pend_user_login, $pend_remote_ip, $pend_sid);
				if (!$rbytes) {
					ETVPN::Logger::log("empty notify connection from $notify_address");
				}
				elsif ( ( ($pend_user_login, $pend_remote_ip, $pend_sid) = $notify_buf =~ /^notify (\S+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ([^\s\r\n]+)/ ) ) {
					# validation notify from CGI
					my $restore_prefix_level = ETVPN::Logger::current_level();
					ETVPN::Logger::push_prefix("user $pend_user_login [$pend_remote_ip] (notify src $notify_address): ");
					my $reply = process_pending_notify($pend_user_login, $pend_remote_ip, $pend_sid);
					ETVPN::Logger::pop_prefix({'level' => $restore_prefix_level});
					print $h "$reply\n";
				}
				elsif ($notify_buf =~ /^status\r?\n$/) {
					# status was requested for monitorization purposes
					my $reply_text = ETVPN::Util::internal_error_text(\%internal_error);
					ETVPN::Logger::log("status request from $notify_address: $reply_text");
					print $h $reply_text."\n";
				}
				else {
					ETVPN::Logger::log("invalid notify attempt from $notify_address");
				}
				$h->close();
			}
		}
	};
	if ($@) {
		if ($@ eq "next\n") {
			next;
		}
		elsif ($@ eq "reload\n") {
			my $old_mgmt_addr = $conf->val('management interface address');
			my $old_mgmt_port = $conf->val('management interface port');
			my $old_notify_port = $conf->val('notify port');
			reload();
			# reconnect to management interface if address changed
			if ($conf->val('management interface address') ne $old_mgmt_addr ||
			    $conf->val('management interface port') ne $old_mgmt_port) {
				ETVPN::Logger::log('openvpn management interface connection parameters changed, reconnecting');
				# also takes care if notify port has changed
				reconnect_to_management_interface();
			}
			elsif ($conf->val('notify port') ne $old_notify_port) {
				$select->remove($notify_h);
				$notify_h->close();
				listen_for_notify_requests();
			}
			next;
		}
		else {
			# propagate other signals
			die $@;
		}
	}
}

# Should never reach here
ETVPN::Logger::fatal_code(3, "Abnormal exit");
