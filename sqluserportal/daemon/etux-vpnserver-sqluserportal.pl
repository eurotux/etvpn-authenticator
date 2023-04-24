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
use Bytes::Random::Secure qw(random_bytes random_bytes_base64);
use IO::Socket qw(AF_INET AF_UNIX);
use IO::Select;
use JSON;
use URI;
use MIME::Base64 qw(encode_base64url);
use Authen::WebAuthn;
use DBI;

use ETVPN::Logger;
use ETVPN::Conf;
use ETVPN::Secret;
use ETVPN::Challenge;
use ETVPN::Util;


#################################
### Globals
#################################
$|=1;
my $need_help = 0;
my $default_ini_file = '/etc/etvpn/sqluserportal.ini';
my $config_file = $default_ini_file;
my $conf;
my $conf_listen_address;
my $conf_listen_port;
my $conf_token_timeout;
my $conf_max_attempts;
my %conf_sql_backends;
my $select = IO::Select->new();
my $req_h;
my @req_sock_opts = (
	Listen    => 256,
	Proto     => 'tcp',
	Reuse     => 1,
);
my $requests = 0;
my $current_token_timeout;
my %tokens;
my %internal_error = (
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

sub clear_token($) {
	my ($tkid) = @_;
	my $count = 0;
	if (defined($tkid) && exists($tokens{$tkid})) {
		# ensure any challenge object on the login object is unreferenced and destroyed first
		# so that when its destructor is invoked any log prefix is still valid
		$tokens{$tkid}->[2]->set_associated_challenge(undef);
		# delete the token
		delete $tokens{$tkid};
		$count++;
	}
	return $count;
}

sub gen_unique_token_key() {
	my $key;
	do {
		$key = random_bytes_base64(20, q{});
	} while (exists($tokens{$key}));
	return $key;
}

sub decode_secret($$) {
	my ($login, $r) = @_;

	# assume error by default, it's the caller's responsibility to change as appropriate
	$r->{'result'} = 'error';
	# decrypt and validate challenge secret
	my $secret_decoder = ETVPN::Secret::new_from_conf($conf) or return undef;
	my $decode_result = $secret_decoder->decode($login);
	unless ($decode_result) {
		ETVPN::Logger::log($secret_decoder->get_errors());
		$internal_error{'SECRET DECODING'} = 1;
		return undef;
	};
	return $decode_result;
}

sub auth_user_pass_verify($$$$) {
	my ($user_login, $user_password, $id, $r) = @_;

	ETVPN::Logger::log("new authentication attempt");
	# Prepare backend
	my $backend_realm = $conf->get_username_backend_realm($user_login) or do {
		ETVPN::Logger::log("login failed: unknown realm");
		$r->{'result'} = 'fail';
		return;
	};
	my ($backend, $user_name, $realm) = @$backend_realm;
	unless ($backend->isa('ETVPN::Backend::SQL')) {
		ETVPN::Logger::log("login failed: attempt to login on non-SQL backend with realm \"$realm\"");
		$r->{'result'} = 'fail';
		return;
	}
	unless (defined($conf_sql_backends{$realm})) {
		ETVPN::Logger::log("login failed: attempt to login on non user portal enabled SQL backend with realm \"$realm\"");
		$r->{'result'} = 'fail';
		return;
	}

	# Credentials validation
	ETVPN::Logger::log("validating on realm: $realm");
	my $login = $backend->validate_login($user_name, $realm, $user_password);
	my $is_backend_internal_error = $backend->has_internal_error();
	$internal_error{'BACKEND'} = $is_backend_internal_error;
	unless ($login && $login->is_success()) {
		# ensure 'login failed: ' is only present on non internal error so that a logged bannable error is distinguishable
		if ($is_backend_internal_error) {
			ETVPN::Logger::log($backend->get_errors());
			ETVPN::Logger::log('rejecting login due to authentication backend internal error');
			$r->{'result'} = 'error';
		}
		else {
			# note: use get_error() and not get_errors() here on purpose so that a login failure is on a single line
			# prepended by the bannable prefix
			my $motive_log = $backend->get_error();
			$motive_log = 'backend validation failed' unless $motive_log;
			ETVPN::Logger::log("login failed: $motive_log");
			$r->{'result'} = 'fail';
		}
		return;
	}
	$login->set_env({});

	# Challenge preparation
	if ($login->has_challenge_secret()) {
		my $decode_result = decode_secret($login, $r) or return;
		my $challenge_type = $decode_result->[0];
		my $challenge;
		if ($challenge_type eq 'otpauth') {
			$r->{'challenge_type'} = 'totp';
			$challenge = ETVPN::Challenge::new_from_type($conf, $challenge_type) or do {
				ETVPN::Logger::log("could not create challenge object of type: $challenge_type");
				$internal_error{'CHALLENGE'} = 1;
				return;
			};
		}
		elsif ($challenge_type eq 'webauthn') {
			$r->{'challenge_type'} = 'webauthn';
			$challenge = random_bytes(32);
			$r->{'challenge'} = [ unpack('C*', $challenge) ];
			$r->{'rpID'} = $conf->val('rp id');
			my $secret = $decode_result->[1];
			$r->{'credential_id'} = [ unpack('C*', $secret->{'credential_id'}) ];
		}
		else {
			ETVPN::Logger::log("rejecting login due to invalid or unsupported challenge type: $challenge_type");
			$r->{'result'} = 'fail';
			return;
		}
		$login->set_associated_challenge($challenge);
	}
	elsif ($conf->val('enforce mfa')) {
		ETVPN::Logger::log('login failed: challenge not configured for user but MFA is enforced, PLEASE REVIEW THIS USER CONFIGURATION');
		$r->{'result'} = 'fail';
		return;
	}

	# Login successful
	my $tkid = gen_unique_token_key();
	# Format for tokens in memory is as follows
	$tokens{$tkid} = [$id, $user_login, $login, time, $conf_max_attempts];
	$r->{'token'} = $tkid;
	$r->{'result'} = 'ok';
	ETVPN::Logger::log("login successful");
}

sub challenge_ok_result($$) {
	my ($token, $r) = @_;
	# clear associated challenge
	$token->[2]->set_associated_challenge(undef);
	# reset max attempts for next possible operations (e.g. changing password)
	$token->[4] = $conf_max_attempts;
	$r->{'result'} = 'ok';
	return 1;
}

sub validate_challenge($$$) {
	my ($tkid, $request, $r) = @_;

	# ensure token did not expire meanwhile
	clean_stale_tokens();
	my $token = $tokens{$tkid} or do {
		ETVPN::Logger::log('could not validate challenge: invalid or expired token');
		$r->{'result'} = 'invalid';
		return 0;
	};
	# sanity validation
	my $login = $token->[2];
	my $challenge = $login->get_associated_challenge() or do {
		ETVPN::Logger::log('attempt to validate challenge on login with no challenge defined or that was already validated');
		$r->{'result'} = 'badrequest';
		return 0;
	};
	my $decode_result = decode_secret($login, $r) or return 0;

	# challenge validation by secret type
	my ($challenge_type, $secret) = @$decode_result;
	if ($challenge_type eq 'otpauth') {
		my $otp_code = $request->{'code'};
		unless (defined($otp_code)) {
			ETVPN::Logger::log('attempt to validate TOTP challenge without providing code');
			$r->{'result'} = 'badrequest';
			return 0;
		}
		my $challenge_validation = $challenge->validate($login, $secret, $otp_code);
		my $is_challenge_internal_error = $challenge->has_internal_error();
		$internal_error{'CHALLENGE'} = $is_challenge_internal_error;
		ETVPN::Logger::log($challenge->get_errors());
		# distinguish failure due to internal error
		if ($is_challenge_internal_error) {
			return 0;
		}
		if ($challenge_validation) {
			return challenge_ok_result($token, $r);
		}
		$r->{'result'} = 'fail';
		return 0;
	}
	elsif ($challenge_type eq 'webauthn') {
		my $authenticator_data;
		my $data;
		my $signature;
		unless ( defined( $authenticator_data = $request->{'authenticator_data'} ) &&
			 defined( $data = $request->{'data'} ) &&
			 defined( $signature = $request->{'signature'} ) ) {
			ETVPN::Logger::log('attempt to validate WebAuthn challenge without providing all parameters');
			$r->{'result'} = 'badrequest';
			return 0;
		}
		my $base_uri = URI->new($conf->val('url base'));
		my $origin = URI->new($base_uri->scheme().'://'.$base_uri->authority())->canonical();
		$origin =~ s~/+$~~;
		my $webauthn_rp = Authen::WebAuthn->new(
			'rp_id'  => $conf->val('rp id'),
			'origin' => $origin,
		);
		my $validation_result = eval {
			$webauthn_rp->validate_assertion(
				challenge_b64 => encode_base64url($challenge, q{}),
				credential_pubkey_b64 => $secret->{'credential_pubkey'},
				stored_sign_count => 0,
				requested_uv => 'discouraged',
				client_data_json_b64   => $data,
				authenticator_data_b64 => $authenticator_data,
				signature_b64 => $signature,
				# we didn't call for any extensions on the request
				extension_results => {},
			);
		};
		if ($@) {
			# some internal errors can occur here, but most likely invalid data was sent by the browser
			# most likely provoked by a tampering attempt, so DON'T flag this as an internal error
			ETVPN::Logger::log("error validating webauthn authorization : $@");
		}
		elsif ($validation_result) {
			ETVPN::Logger::log("webauthn authorization successful");
			return challenge_ok_result($token, $r);
		}
		ETVPN::Logger::log("webauthn authorization failed");
		$r->{'result'} = 'fail';
		return 0;
	}
	else {
		ETVPN::Logger::log("rejecting login due to invalid or unsupported challenge type: $challenge_type");
	}

	return 0;
}

sub change_password($$$) {
	my ($tkid, $request, $r) = @_;

	ETVPN::Logger::log('password change requested');
	# ensure token did not expire meanwhile
	clean_stale_tokens();
	my $token = $tokens{$tkid} or do {
		ETVPN::Logger::log('could not change password: invalid or expired token');
		$r->{'result'} = 'invalid';
		return 0;
	};
	# sanity validation
	$r->{'result'} = 'error';
	my $login = $token->[2];
	if ($login->get_associated_challenge()) {
		ETVPN::Logger::log('attempt to change password before validating challenge');
		$r->{'result'} = 'badrequest';
		return 0;
	};
	my $old_password;
	my $new_password;
	unless ( defined( $old_password = $request->{'old_password'} ) &&
		 defined( $new_password = $request->{'new_password'} ) ) {
		ETVPN::Logger::log('attempt to change password without providing all parameters');
		$r->{'result'} = 'badrequest';
		return 0;
	}
	if ($old_password eq $new_password) {
		ETVPN::Logger::log('attempt to change password to the same old password');
		$r->{'result'} = 'same';
		return 0;
	}
	unless (ETVPN::Util::is_strong_password($new_password)) {
		ETVPN::Logger::log('attempt to change password to a weak password');
		$r->{'result'} = 'weak';
		# return 1 so that this particular result does not affect attempt count
		return 1;
	}
	# prepare backend
	my $backend_realm = $conf->get_username_backend_realm($token->[1]) or do {
		ETVPN::Logger::log('could not get backend data while changing password');
		return 0;
	};
	my ($backend, $user_name, $realm) = @$backend_realm;
	my $db_username = $conf_sql_backends{$realm}{'username'};
	my $db_password = $conf_sql_backends{$realm}{'password'};
	if ($db_username && $db_password) {
		unless ($backend->connect_as($db_username, $db_password)) {
			ETVPN::Logger::log($backend->get_error);
			return 0;
		}
	}
	# get and perform sanity check on user id and current crypted password
	my $row = $backend->userdata_from_db($user_name, $realm, 'id', 'password');
	unless ($backend->check_row($row, 'id', 'password')) {
		ETVPN::Logger::log($backend->get_error);
		return 0;
	}
	# check old password
	my $crypted_password = $row->{'password'};
	if (crypt($old_password, $crypted_password) ne $crypted_password) {
		ETVPN::Logger::log('authentication failure attempting to change password');
		$r->{'result'} = 'fail';
		return 0;
	}
	# attempt to change password
	my $dbh = $backend->db_object() or do {
		ETVPN::Logger::log($backend->get_error);
		return 0;
	};
	my $db_id = $row->{'id'};
	my $bconf = $backend->get_conf();
	my $result = $dbh->do('UPDATE '.$bconf->val('users table').' SET '.$bconf->val('users col password').'='.$dbh->quote(ETVPN::Util::strong_crypt($new_password)).' WHERE '.$bconf->val('users col id').'='.$dbh->quote($db_id));
	if ($result) {
		ETVPN::Logger::log("updated password for user \"$user_name\" with ID $db_id on SQL database of realm \"$realm\"");
		$r->{'result'} = 'ok';
		return 1;
	}
	ETVPN::Logger::log('database update query failed while changing password: '.$DBI::errstr);
	return 0;
}

sub listen_for_requests() {
	$req_h = IO::Socket::INET->new(@req_sock_opts, LocalAddr => $conf_listen_address, LocalPort => $conf_listen_port)
		or ETVPN::Logger::fatal_code(4, "error listening for requests: $!");
	$select->add($req_h);
	ETVPN::Logger::log("Listening for requests on $conf_listen_address:$conf_listen_port");
}

sub clean_stale_tokens() {
	foreach my $tkid (keys %tokens) {
		my $token = $tokens{$tkid};
		if (time - $token->[3] >= $conf_token_timeout) {
			my $reqno = $token->[0];
			my $username = $token->[1];
			# push prefix to logger class to associate it to messages of cleaned objects triggered by garbage collection
			# (note: should work, since perl supposedly destroys objects as soon as their reference count drops to zero,
			# but in reality the object destruction is delayed, at least as of perl 5.34)
			ETVPN::Logger::push_prefix("user $username [request $reqno]: ");
			ETVPN::Logger::log('token time out');
			clear_token($tkid);
			ETVPN::Logger::pop_prefix();
		}
	}
	$current_token_timeout = $conf_token_timeout;
}

sub load_configuration(;$) {
	my $is_reload = shift;
	# Load this daemon specific configuration
	my $cfg = ETVPN::Conf::load_ini_config($config_file) or ETVPN::Conf::confdie("Error(s) found getting settings from $config_file" .(@Config::IniFiles::errors ? ': '.join("\n", @Config::IniFiles::errors) : ''));
	my $etux_vpn_server_ini = ETVPN::Conf::get_mandatory($cfg, 'global', 'etux vpn server ini');
	$conf_listen_address = ETVPN::Conf::get_mandatory($cfg, 'global', 'listen address');
	$conf_listen_port = ETVPN::Conf::get_mandatory($cfg, 'global', 'listen port');
	$conf_token_timeout = ETVPN::Conf::get_mandatory_in_range($cfg, 'global', 'token timeout', 'uint', 600, 60);
	$conf_max_attempts = ETVPN::Conf::get_mandatory_in_range($cfg, 'global', 'max attempts', 'uint', 3, 1);
	if ($is_reload) {
		$conf->reload($etux_vpn_server_ini);
	}
	else {
		# Load main configuration (dies on error)
		$conf = ETVPN::Conf->new($etux_vpn_server_ini, 1);
	}
	$cfg->DeleteSection('global');
	# Load enabled SQL backends sections
	foreach my $section ($cfg->Sections()) {
		if ( my ($realm, $type) = $section =~ /^backend (\S+) (\S+)$/ ) {
			ETVPN::Conf::confdie("invalid backend \"$realm\" in user portal (must be a SQL backend)") unless $type eq 'sql';
			next unless ETVPN::Conf::get_mandatory_in_range($cfg, $section, 'enabled', 'bool', 0);
			my $backend = $conf->get_backend($realm) or ETVPN::Conf::confdie("backend \"$realm\" enabled in user portal does not exist in main config file");
			unless ($backend->isa('ETVPN::Backend::SQL')) {
				ETVPN::Conf::confdie("backend \"$realm\" enabled in user portal does not correspond to a SQL backend in main config file (type mismatch)");
			}
			my ($be_conf, $u, $p);
			$conf_sql_backends{$realm} = $be_conf = {};
			$u = $be_conf->{'username'} = ETVPN::Conf::get_mandatory($cfg, $section, 'database username', '');
			$p = $be_conf->{'password'} = ETVPN::Conf::get_mandatory($cfg, $section, 'database password', '');
			if ( ($u || $p) && !($u && $p) ) {
				ETVPN::Conf::confdie("user portal SQL backend \"$realm\": must specify both username and password, or omit both");
			}
		}
		else {
			ETVPN::Conf::confdie("invalid section: [$section]");
		}
	}
	unless (scalar %conf_sql_backends) {
		ETVPN::Conf::confdie('must have at least one SQL backend enabled in user portal configuration')
	}
}

sub reload() {
	local $SIG{HUP} = 'IGNORE';
	ETVPN::Logger::log('reloading configuration...');
	load_configuration(1);
	# since a reload can also interrupt, handle stale tokens if needed
	clean_stale_tokens();
	ETVPN::Logger::log('completed reloading configuration');
}

sub throw_reload {
	ETVPN::Logger::log("configuration reload requested");
	die "reload\n";
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

# Load configuration
load_configuration();

# Show an extra prefix when running in terminal
# Not needed if running as a service
if (is_interactive()) {
	ETVPN::Logger::push_prefix(sub { strftime('%Y-%m-%d %H:%M:%S %z', localtime) }, ' '.basename($0, '.pl').": ");
}

my $token_cleanup_ts;
$current_token_timeout = $conf_token_timeout;

$SIG{USR1} = \&throw_reload;
listen_for_requests();

my $logout_reply = '{"type":"logout","result":"ok"}';

while (1) {
	# some modules mess up the signal handling, ensure it's restored on each iteration
	$SIG{HUP} = \&throw_reload;

	# exception catching, for handling reloads safely
	eval {
		$token_cleanup_ts = time;
		$! = 0;
		my @ready = $select->can_read($current_token_timeout >= 0 ? $current_token_timeout : 1);
		unless (@ready) {
			if ($!) {
				ETVPN::Logger::log("IO::Select error: $!");
			}
			else {
				# timeout reached
				clean_stale_tokens();
			}
			die "next\n";
		}
		if ( ($current_token_timeout -= time - $token_cleanup_ts) <= 0) {
			clean_stale_tokens();
		}
		foreach my $h (@ready) {
			if ($h == $req_h) {
				# new request (from web GUI)
				my $new = $req_h->accept();
				if (defined($new)) {
					$new->blocking(0);
					my $req_address = $new->peerhost().':'.$new->peerport();
					ETVPN::Logger::log("new connection from $req_address");
					$select->add($new);
				}
				else {
					ETVPN::Logger::log("error accepting connection: $!");
				}
			}
			else {
				# process connection request
				my $req_address = $h->peerhost().':'.$h->peerport();
				my $restore_prefix_level = ETVPN::Logger::current_level();
				ETVPN::Logger::push_prefix("from $req_address: ");
				my $req_buf;
				my $rbytes = sysread $h, $req_buf, 1024;
				my ($pend_user_login, $pend_remote_ip, $pend_sid);
				if (!$rbytes) {
					ETVPN::Logger::log("connection closed remotely");
					$select->remove($h);
					$h->close();
				}
				else {
					my $reply;
					my $result;
					my $tkid;
					if ($req_buf =~ /^status\r?\n$/) {
						# status was requested for monitorization purposes
						$reply = ETVPN::Util::internal_error_text(\%internal_error);
						ETVPN::Logger::log("status request: $reply");
					}
					else {
						my $type;
						my $token;
						my $request = eval { from_json($req_buf) };
						if ($@) {
							ETVPN::Logger::log("invalid request: JSON error: $@");
						}
						elsif (defined( $type = $request->{'type'} )) {
							if ($type eq 'login') {
								my $username;
								my $password;
								if (!defined( $username = $request->{'username'} )) {
									ETVPN::Logger::log("invalid login request: missing username");
								}
								elsif (!defined( $password = $request->{'password'} )) {
									ETVPN::Logger::log("invalid login request: missing password");
								}
								else {
									my $reqno = ++$requests;
									ETVPN::Logger::push_prefix("user $username [request $reqno]: ");
									my $r = { 'type' => 'login' };
									auth_user_pass_verify($username, $password, $reqno, $r);
									$reply = encode_json $r;
								}
							}
							elsif (!defined( $tkid = $request->{'token'} )) {
								ETVPN::Logger::log("invalid request with missing token, attempted type: $type");
							}
							elsif (!defined( $token = $tokens{$tkid} )) {
								ETVPN::Logger::log("invalid or expired token, attempted type: $type");
								if ($type eq 'logout') {
									# logout should always return ok even if token has expired
									$reply = $logout_reply;
								}
								else {
									$reply = encode_json {'type' => $type, 'result' => 'invalid'};
								}
							}
							else {
								my $reqno = $token->[0];
								my $username = $token->[1];
								ETVPN::Logger::push_prefix("user $username [request $reqno]: ");
								my $r = { 'type' => $type };
								if ($type eq 'challenge_authorization') {
									if (!validate_challenge($tkid, $request, $r) && --$token->[4] <= 0) {
										clear_token($tkid);
										ETVPN::Logger::log('token invalidated due to maximum number of challenge attempts reached');
									}
									$reply = encode_json $r;
								}
								elsif ($type eq 'check') {
									my $user_login = $request->{'username'};
									if (defined($user_login) && $user_login eq $username) {
										ETVPN::Logger::log('token check successful');
										$r->{'result'} = 'ok';
									}
									else {
										ETVPN::Logger::log('token check failed');
										clear_token($tkid);
										$r->{'result'} = 'invalid';
									}
									$reply = encode_json $r;
								}
								elsif ($type eq 'passwd') {
									if (!change_password($tkid, $request, $r) && --$token->[4] <= 0) {
										clear_token($tkid);
										ETVPN::Logger::log('token invalidated due to maximum number of password changing attempts reached');
									}
									$reply = encode_json $r;
								}
								elsif ($type eq 'logout') {
									clear_token($tkid);
									ETVPN::Logger::log("logout");
									$reply = $logout_reply;
								}
								else {
									ETVPN::Logger::log("invalid request, attempted type: $type");
								}
								$result = $r->{'result'};
							}
						}
						else {
							ETVPN::Logger::log("invalid request: missing type");
						}
					}
					# invalidate any token after a bad request
					if ((!defined($reply) || !defined($result) || $result eq 'badrequest') && clear_token($tkid)) {
						ETVPN::Logger::log('token invalidated due to bad request');
					}
					print $h (defined($reply) ? $reply : '{"result":"badrequest"}')."\r\n";
				}
				ETVPN::Logger::pop_prefix({'level' => $restore_prefix_level});
			}
		}
	};
	if ($@) {
		if ($@ eq "next\n") {
			next;
		}
		elsif ($@ eq "reload\n") {
			my $old_address = $conf_listen_address;
			my $old_port = $conf_listen_port;
			reload();
			if ($conf_listen_address ne $old_address || $conf_listen_port ne $old_port) {
				$select->remove($req_h);
				$req_h->close();
				listen_for_requests();
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
