#!/usr/bin/plackup
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
use File::Basename;
use Plack::Request;
use URI;
use CGI::Session;
use HTML::Template;
use JSON;
use MIME::Base64 qw(encode_base64url decode_base64url);
use IO::Socket qw(AF_INET AF_UNIX);
use Net::IP;

use ETVPN::Web;
use ETVPN::Session;

# Flush by line
$| = 1;

# Globals
my $session_cookie_name = 'ETVPNUPSID';
my $session_base_dir = $ENV{'ETVPN_USERPORTAL_SESSION_BASE_DIR'};
my $daemon_address = $ENV{'ETVPN_USERPORTAL_DAEMON_ADDRESS'};
my $daemon_port = $ENV{'ETVPN_USERPORTAL_DAEMON_PORT'};
my $daemon_h;
my %logout_reasons = (
	'logout' => 'logged out',
	'expired' => 'deleting expired session',
);
my $session;
my $type;
my $basepath;

# Initialize allow list
my @allowed_from;
if ( ( my $allowed = $ENV{'ETVPN_USERPORTAL_ALLOWED'} ) ) {
	my %allowed_filter;
	foreach my $addr (split(/\s+/, $allowed)) {
		next if exists($allowed_filter{$addr});
		my $ip = new Net::IP($addr) or do {
		};
		$allowed_filter{$addr} = 1;
		push @allowed_from, $ip;
	}
}


sub logmsg($$) {
	my $sess_details = '';
	if (valid_session()) {
		$sess_details .= ': session '.$session->id();
		if ( ( my $username = $session->param('username') ) ) {
			$sess_details .= " user $username";
		}
	}
	print STDERR 'etvpn sqluserportal ['.$_[0]->address()."]$sess_details: ".$_[1]."\n";
}

sub defined_equal($$) {
	my ($var, $value) = @_;
	return defined($var) && $var eq $value;
}

sub all_defined_in_hash($@) {
	my $h = shift;
	my @r;
	foreach my $k (@_) {
		my $v = $h->{$k};
		return undef unless defined($v);
		push @r, $k, $v;
	}
	return \@r;
}

sub clear() {
	$session = $type = $basepath = undef;
}

sub valid_session() {
	return $session && $session->id();
}

sub has_button($$) {
	my ($p_params, $btn) = @_;
	return defined_equal($p_params->{$btn}, '1');
}

sub connect_daemon($) {
	my $req = shift;
	my $action_type;
	if ($daemon_h) {
		$action_type = 'reconnecting';
		$daemon_h->close();
	}
	else {
		$action_type = 'connecting';
	}
	logmsg($req, "$action_type to user portal daemon at $daemon_address:$daemon_port");
	$daemon_h = IO::Socket::INET->new(
		PeerAddr => $daemon_address,
		PeerPort => $daemon_port,
		Proto    => 'tcp',
		Type     => IO::Socket::SOCK_STREAM,
		Timeout  => 10
	) or do {
		logmsg($req, "error connecting to user portal daemon: $!");
		return undef;
	};
	logmsg($req, 'connected to user portal daemon as '.$daemon_h->sockhost().':'.$daemon_h->sockport());
	$daemon_h->autoflush(1);
}

sub request_daemon($$) {
	my ($req, $jreq) = @_;
	unless ($daemon_h) {
		connect_daemon($req) or return undef;
	}
	my $json = encode_json($jreq);
	# reconnect and retry once
	my $jreply_txt;
	for (my $i = 0; $i < 2; $i++) {
		my $sent = eval { $daemon_h->send("$json\r\n") };
		if ($@ || !$sent) {
			logmsg($req, "lost connection to user portal daemon (could not send request)");
			connect_daemon($req);
		}
		else {
			$jreply_txt = $daemon_h->getline();
			if ($jreply_txt) {
				last;
			}
			else {
				logmsg($req, "lost connection to user portal daemon (got empty reply)");
				connect_daemon($req);
			}
		}
	}
	unless ($jreply_txt) {
		logmsg($req, "could not receive reply from user portal daemon");
		return undef;
	};
	my $jreply = eval { from_json($jreply_txt) };
	if ($@) {
		logmsg($req, "invalid JSON reply from user portal daemon: $@");
		return undef;
	};
	return $jreply;
}

sub daemon_error_reply($) {
	my $jreply = shift;
	my $result;
	if ( !$jreply || !( $result = $jreply->{'result'} ) ) {
		return ['error', 'invalid user portal daemon reply (empty or missing result)'];
	};
	if ($result =~ /^(badrequest|error)$/) {
		return ['error', "user portal daemon replied with worrying result: $result"];
	}
	if ($result eq 'invalid') {
		return ['expired', 'invalid or expired token'];
	}
	return undef;
}

sub delete_session($) {
	my $req = shift;
	return unless $session;
	my $sid = $session->id();
	$session->delete();
	if ($sid) {
		if ($session->flush()) {
			logmsg($req, "session $sid deleted");
		}
		else {
			logmsg($req, "flush error when deleting session $sid: ".$session->errstr());
		}
	}
	$session = undef;
}

sub flush_session_error() {
	return unless valid_session();
	my $saved_umask = umask;
	umask(0117);
	my $flush_success = $session->flush();
	umask($saved_umask);
	return $flush_success ? 0 : "flush error when attempting to store session ".$session->id()." data: ".$session->errstr();
}

sub json_reply($$$$) {
	my ($req, $status, $result, $message) = @_;
	my $jreply = { 'result' => $result, 'message' => $message };
	return [ $status, ['Content-Type' => 'application/json; charset=utf8'], [encode_json($jreply)] ];
}

sub end_request($$) {
	my ($req, $logreason) = @_;

	# Despite not showing in browser, we always log the real reason
	logmsg($req, $logreason);

	# Send JSON reply when requested, so that the browser correctly reports an expired session to a legitimate user webauthn attempt
	my $response;
	my $content_type;
	if (defined($req) &&
	    defined($content_type = $req->headers->content_type) &&
	    $content_type eq 'application/json' &&
	    $req->method eq 'POST') {
		$response = json_reply($req, 410, 'expired', 'Request has expired');
	}
	else {
		$response = [302, ['Location' => "$basepath/error"], []];
		if ($type) {
			if ($type eq 'error') {
				$response = [500, [], ['An internal error occurred, please contact the system administrator.']];
			}
			elsif ($type =~ /^redirect_(.+)$/) {
				$response = [302, ['Location' => "$basepath/$1"], []];
			}
		}
	}

	# Delete or invalidate session
	if (valid_session()) {
		logmsg(
			$req,
			$type && $type =~ /^(?:redirect_)?(expired|logout)$/ ? $logout_reasons{$1} : 'deleting invalid session'
		);
		# This will force next load to show login page (for logout, error and expired types)
		delete_session($req);
	}

	clear();
	return $response;
}

sub end_request_daemon_error($$$;$) {
	my ($req, $d_err, $during, $session) = @_;
	$type = 'redirect_'.$d_err->[0];
	return end_request($req, "$during: ".$d_err->[1]);
}

sub logout_response($$) {
	my ($req, $session) = @_;
	$type = 'redirect_logout';
	return end_request($req, 'redirect to logout');
}

# All requests must be relative to the base path and terminated by a valid command, or have no command (default start page)
sub request_url_params($$) {
	my ($env, $req) = @_;
	my $req_uri;
	my $path;
	if ( defined( $req_uri = $req->request_uri() ) &&
	     defined( $path = URI->new($req_uri)->path ) ) {
		if ( my ($slash, $rtype) = $path =~ m~^\Q$basepath\E(?:(/)(error|logout|expired)?)?$~ ) {
			# for base URL, redirect to address ending with a slash as needed (or else cookies will get messed up)
			return defined($rtype) ? $rtype : $slash ? 'start' : 'redirect_start';
		}
	}
	return undef;
}

sub new_session($$$) {
	my ($req, $username, $sess_opts) = @_;
	my $sess_error;
	$session = eval {
		local $ENV{REMOTE_ADDR} = $req->address;
		CGI::Session->new(ETVPN::Session::dsn, ETVPN::Session::safe_session_name($sess_opts), $sess_opts);
	};
	if (valid_session()) {
		logmsg($req, 'new session');
	}
	else {
		$sess_error = "error creating session: ".CGI::Session->errstr();
	}
	return $sess_error;
}

sub load_session($$) {
	my ($req, $sess_opts) = @_;
	my $sid = $req->cookies->{$session_cookie_name};
	my $sess_error;
	if (defined($sid) && $sid ne 'none') {
		$session = CGI::Session->load(ETVPN::Session::dsn, $sid, $sess_opts);
		if ($type =~ /^(error|logout|expired)$/) {
			delete_session($req);
			return undef;
		}
		unless ($session && !$session->is_empty && $session->id()) {
			$type = 'redirect_expired';
			$sess_error = "invalid or expired session $sid";
		}
		elsif ($req->address ne $session->remote_addr()) {
			$sess_error = 'mismatched session origin address '.$session->remote_addr.', forcing new session creation for this user agent';
		}
		else {
			logmsg($req, "resuming session");
		}
	}
	delete_session($req) if $sess_error;
	return $sess_error;
}

sub cookie_header() {
	my ($value, $expires);
	if (valid_session()) {
		$value = $session->id();
		# Always use session cookies, whose effective lifetime is controlled by the daemon
		$expires = '';
	}
	else {
		$value = 'none';
		$expires = "; expires=Thu, 01 Jan 1970 00:00:00 GMT";
	}
	return ('Set-Cookie' => "$session_cookie_name=$value; path=$basepath/; SameSite=Lax$expires");
}

sub is_allowed_access($) {
	my $req = shift;
	return 1 unless @allowed_from;
	my $addr = new Net::IP($req->address()) or do {
		logmsg($req, 'denied access (invalid remote address)');
		return 0;
	};
	foreach my $ip (@allowed_from) {
		my $overlaps = $ip->overlaps($addr);
		if ($overlaps == $IP_B_IN_A_OVERLAP || $overlaps == $IP_IDENTICAL) {
			return 1;
		}
	}
	logmsg($req, 'denied access (not in ETVPN_USERPORTAL_ALLOWED)');
	return 0;
}

sub disallow_access() {
	if ( ( my $redirect_disallowed = $ENV{'ETVPN_USERPORTAL_REDIRECT_DISALLOWED'} ) ) {
		return [302, ['Location' => $redirect_disallowed], []];
	}
	return [403, [], ['<h1>Forbidden</h1>']];
}


##### Main
my $app = sub {
	my $env = shift;
	ETVPN::Web::translate_port_share($env);
	$basepath = $env->{'CONTEXT_PREFIX'};
	$basepath = '' unless defined($basepath);
	$type = '';
	my $req = Plack::Request->new($env) or
		return end_request(undef, "Could not get a valid Plack::Request");

	# check access
	unless (is_allowed_access($req)) {
		return disallow_access();
	}

	# get request parameters
	$type = request_url_params($env, $req);
	# confirm if parameters and request method are valid
	if (!$type || $req->method() !~ /(?:GET|POST)/) {
		my $req_uri = $req->request_uri();
		return end_request($req, 'invalid '.$req->method().' request attempted'.($req_uri ? " on $req_uri" : ''));
	};
	if ($type eq 'redirect_start') {
		return [302, ['Location' => "$basepath/"], []];
	}

	# Check if mandatory environment variables are defined
	return end_request($req, "ETVPN_USERPORTAL_SESSION_BASE_DIR not defined, please check your PSGI server configuration") unless $session_base_dir;
	return end_request($req, "ETVPN_USERPORTAL_DAEMON_ADDRESS not defined, please check your PSGI server configuration") unless $daemon_address;

	# Load existing session
	my $err_reply = load_session($req, { Directory => $session_base_dir });
	return end_request($req, $err_reply) if defined($err_reply);

	my $template = HTML::Template->new(filename => 'sqluserportal.tmpl', default_escape => 'html');
	$template->param(
		BASEPATH => $basepath,
	);
	my $code = 200;
	my $stage = 'login';
	my $token;
	if ($type eq 'start') {
		if (valid_session()) {
			my $username = $session->param('username') or return end_request($req, 'invalid session on start page: missing username');
			$token = $session->param('token') or return end_request($req, 'invalid session on start page: missing token');
			$stage = $session->param('stage') or return end_request($req, 'invalid session on start page: missing stage');
			my $jreply = request_daemon($req, { 'type' => 'check', 'username' => $username, 'token' => $token });
			if ( ( my $d_err = daemon_error_reply($jreply) ) ) {
				return end_request_daemon_error($req, $d_err, 'session check');
			}
			if ($jreply->{'result'} ne 'ok') {
				return end_request($req, 'unexpected response from daemon while checking session');
			}
		}

		# form validation by stage
		if ($req->method() eq 'POST') {
			my $p_params = $req->body_parameters;
			if ($stage eq 'login' && has_button($p_params, 'login')) {
				# login attempt
				my ($username, $password) = ($p_params->{'uname'}, $p_params->{'psw'});
				unless (defined($username) && defined($password)) {
					# bannable error
					return end_request($req, 'tampering attempt: missing login credentials');
				}
				my $jreply = request_daemon($req, { 'type' => 'login', 'username' => $username, 'password' => $password });
				if ( ( my $d_err = daemon_error_reply($jreply) ) ) {
					return end_request_daemon_error($req, $d_err, 'login');
				}
				if ($jreply->{'result'} ne 'ok') {
					# bannable error
					logmsg($req, "login failure: invalid credentials (username: $username)");
					$template->param(
						ERROR => 'Login incorrect',
					);
				}
				else {
					logmsg($req, "login successful for user: $username");
					my @new_params = ('username' => $username);
					my $token = $jreply->{'token'} or end_request($req, 'missing token from daemon during login');
					push @new_params, 'token' => $token;
					my $challenge_type = $jreply->{'challenge_type'};
					if (defined($challenge_type)) {
						if ($challenge_type eq 'webauthn') {
							my $params = all_defined_in_hash($jreply, 'challenge', 'rpID', 'credential_id') or return end_request($req, 'received invalid daemon response indicating need for webauthn but missing mandatory parameters');
							push @new_params, @$params;
							$stage = 'webauthn';
						}
						elsif ($challenge_type eq 'totp') {
							$stage = 'totp';
						}
						else {
							return end_request($req, "received invalid daemon response indicating invalid challenge type: $challenge_type");
						}
						push @new_params, 'challenge_type' => $challenge_type;
					}
					else {
						$stage = 'menu';
					}
					# create fresh session after successful login
					delete_session($req);
					my $err_reply;
					$err_reply = new_session($req, $username, { Directory => $session_base_dir });
					return end_request($req, $err_reply) if defined($err_reply);
					$session->param(@new_params, 'stage' => $stage);
				}
			}
			elsif (!valid_session() || !$token) {
				# login is the only stage allowed without a session, so this should not occur but if it does log it
				return end_request($req, 'ERROR: arrived to non-login stage without a session or a token');
			}
			elsif ($stage eq 'webauthn') {
				my $content_type = $req->headers->content_type;
				if (defined($content_type) &&
				    $content_type eq 'application/json') {
					# check JSON reply to webauthn authentication
					my $status = 400;  # Bad request unless validated
					# note: webauthn results should not be confused with user portal daemon protocol
					# 'invalid' here means report to user that they sent invalid data
					# if the request has expired, this will be 'expired'
					my $result = 'invalid';
					my $message = 'Your browser sent invalid data, please ensure it is updated';
					my $client_reply = eval { decode_json($req->content) };
					if ($@) {
						# bannable error
						logmsg($req, "tampering attempt: invalid JSON data received from webauthn authentication: $@");
					}
					elsif ( !all_defined_in_hash($client_reply, 'data', 'authenticator_data', 'signature') ) {
						# bannable error
						logmsg($req, "tampering attempt: invalid or incomplete reply data during webauthn authentication");
					}
					else {
						my $jreply = request_daemon($req, { 'type' => 'challenge_authorization', 'token' => $token, 'code' => $code, 'authenticator_data' =>  $client_reply->{'authenticator_data'}, 'data' =>  $client_reply->{'data'}, 'signature' =>  $client_reply->{'signature'} });
						if ( ( my $d_err = daemon_error_reply($jreply) ) ) {
							logmsg($req, 'webauthn: '.$d_err->[1]);
							$result = $d_err->[0];
							if ($result eq 'expired') {
								return end_request_daemon_error($req, $d_err, 'webauthn');
							}
							$status = 500;
							$message = 'Server error';
						}
						elsif ($jreply->{'result'} eq 'ok') {
							logmsg($req, 'webauthn authentication successful');
							$session->param('stage' => 'menu');
							$result = 'ok';
							$status = 200;
							$message = 'Success';
						}
						else {
							# bannable error
							logmsg($req, 'authentication failure: incorrect webauthn reply');
							$result = 'badauth';
							$status = 403;
							$message = 'Authentication failure';
						}
					}
					clear();
					return json_reply($req, $status, $result, $message)
				}
				elsif (has_button($p_params, 'logout')) {
					# User pressed Logout button in webauthn page
					return logout_response($req, $session);
				}
				# else assume retry button was pressed
			}
			elsif ($stage eq 'totp') {
				if (has_button($p_params, 'authenticate')) {
					# user entered TOTP code
					my $code = $p_params->{'code'};
					unless (defined($code)) {
						# bannable error
						return end_request($req, 'tampering attempt: missing TOTP code');
					}
					else {
						my $jreply = request_daemon($req, { 'type' => 'challenge_authorization', 'token' => $token, 'code' => $code });
						if ( ( my $d_err = daemon_error_reply($jreply) ) ) {
							return end_request_daemon_error($req, $d_err, 'totp');
						}
						if ($jreply->{'result'} eq 'ok') {
							logmsg($req, 'TOTP authentication successful');
							$stage = 'menu';
							$session->param('stage' => $stage);
						}
						else {
							# bannable error
							logmsg($req, 'authentication failure: incorrect TOTP code');
							$template->param(
								ERROR => 'Incorrect code',
							);
						}
					}
				}
				elsif (has_button($p_params, 'logout')) {
					# User pressed Logout button in totp page
					return logout_response($req, $session);
				}
			}
			elsif ($stage eq 'menu') {
				if (has_button($p_params, 'change_pass')) {
					$stage = 'change_password';
					$session->param('stage' => $stage);
				}
				elsif (has_button($p_params, 'logout')) {
					return logout_response($req, $session);
				}
			}
			elsif ($stage eq 'change_password') {
				if (has_button($p_params, 'change_password')) {
					# user attempted to change password
					my $oldpsw = $p_params->{'oldpsw'};
					my $newpsw =$p_params->{'newpsw'};
					my $newpswconfirm = $p_params->{'newpswconfirm'};
					unless (defined($oldpsw) && defined($newpsw) && defined($newpswconfirm)) {
						# bannable error
						return end_request($req, 'tampering attempt: missing fields while attempting to change password');
					}
					if ($newpsw ne $newpswconfirm) {
						logmsg($req, 'password confirmation mismatch while attempting to change password');
						$template->param(ERROR => 'Password confirmation mismatch');
					}
					else {
						my $jreply = request_daemon($req, { 'type' => 'passwd', 'token' => $token, 'code' => $code, 'old_password' => $oldpsw, 'new_password' => $newpsw });
						if ( ( my $d_err = daemon_error_reply($jreply) ) ) {
							return end_request_daemon_error($req, $d_err, 'change password');
						}
						my $result = $jreply->{'result'};
						if ($result eq 'ok') {
							logmsg($req, 'password changed');
							$template->param(SUCCESS => 'Password changed successfully');
							$stage = 'menu';
							$session->param('stage' => $stage);
						}
						elsif ($result eq 'same') {
							logmsg($req, 'change to same old password attempted');
							$template->param(ERROR => 'New password and old password cannot be the same');
						}
						elsif ($result eq 'weak') {
							logmsg($req, 'change to weak password attempted');
							$template->param(ERROR => 'New password is too weak');
						}
						elsif ($result eq 'fail') {
							# bannable error
							logmsg($req, 'authentication failure while attempting to change password');
							$template->param(ERROR => 'Old password is incorrect');
						}
						else {
							return end_request($req, "received invalid daemon result while changing password: $result");
						}
					}
				}
				elsif (has_button($p_params, 'cancel')) {
					$stage = 'menu';
					$session->param('stage' => $stage);
				}
			}
		}
	}
	elsif ($type eq 'error') {
		$template->param(
			ERROR => 'An error has occurred, please try again',
		);
	}
	elsif ($type eq 'logout') {
		$template->param(
			ERROR => 'Logged out successfully',
		);
	}
	elsif ($type eq 'expired') {
		$template->param(
			ERROR => 'Session expired, please login again',
		);
	}
	else {
		my $req_uri = $req->request_uri();
		return end_request($req, 'invalid '.$req->method().' request attempted'.($req_uri ? " on $req_uri" : ''));
	}

	# show layout according to stage
	if ($stage eq 'login') {
		# for expired sessions, error or logout, always ensure session is cleared
		delete_session($req);
		$template->param(LOGIN => 1);
	}
	elsif ($stage eq 'webauthn') {
		$template->param(
			WEBAUTHN => 1,
			CHALLENGE => encode_json($session->param('challenge')),
			RP_ID => $session->param('rpID'),
			CREDENTIAL_ID => encode_json($session->param('credential_id')),
			TIMEOUT => 60000, # TODO: fixed value atm, can't just be derived from "until"
		);
	}
	elsif ($stage eq 'totp') {
		$template->param(TOTP => 1);
	}
	elsif ($stage eq 'menu') {
		$template->param(MENU => 1);
	}
	elsif ($stage eq 'change_password') {
		$template->param(PASSWORD => 1);
	}

	my $response = [$code, ['Content-Type' => 'text/html; charset=utf8', cookie_header()], [$template->output]];

	if ( (my $flush_error = flush_session_error()) ) {
		$type = 'redirect_error';
		return end_request($req, $flush_error);
	}
	clear();
	return $response;
};
