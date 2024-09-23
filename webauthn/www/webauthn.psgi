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
use Bytes::Random::Secure;
use Authen::WebAuthn;
use IO::Socket qw(AF_INET AF_UNIX);

use ETVPN::Web;
use ETVPN::Session;

# Flush by line
$| = 1;


sub logmsg($$) {
	print STDERR 'etvpn webauthn ['.$_[0]->address().']: '.$_[1]."\n";
}

sub delete_session($$) {
	my ($req, $session) = @_;
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
}

sub json_reply($$$$;$) {
	my ($req, $status, $result, $message, $submessage) = @_;
	my $jreply = { 'result' => $result, 'message' => $message };
	$jreply->{'submessage'} = $submessage if $submessage;
	return [ $status, ['Content-Type' => 'application/json; charset=utf8'], [encode_json($jreply)] ];
}

sub invalid_request($$;$) {
	my ($req, $logreason, $session) = @_;
	# Always output the same generic error with 404 status to the browser, in order to not reveal too much information

	# Send JSON reply when requested, so that the browser correctly reports an expired session to a legitimate user attempt
	my $response;
	my $content_type;
	if (defined($req) &&
	    defined($content_type = $req->headers->content_type) &&
	    $content_type eq 'application/json' &&
	    $req->method eq 'POST') {
		$response = json_reply($req, 404, 'NOTFOUND', 'Invalid or expired request', 'Please close this window and try again');
	}
	else {
		$response = [404, ['Content-Type' => 'text/html; charset=utf8'], ["Invalid, expired or not found request\n"]];
	}

	# Despite not showing in browser, we always log the real reason
	my $msg = $session ? 'session '.$session->id().': ' : '';
	$msg .= $logreason;
	logmsg($req, $logreason);

	if ($session) {
		logmsg($req, 'deleting invalid session '.$session->id());
		delete_session($req, $session);
	}

	return $response;
}

# All requests must be relative to the base path and terminated by /authorize/SESSION or /register/SESSION
sub request_params($$) {
	my ($env, $req) = @_;
	my $req_uri;
	my $path;
	if ( defined( $req_uri = $req->request_uri() ) &&
	     defined( $path = URI->new($req_uri)->path ) ) {
		my $basepath = $env->{'CONTEXT_PREFIX'};
		$basepath = '' unless defined($basepath);
		if ( my ($rtype, $rsid) = $path =~ m~^\Q$basepath\E/(authorize|register)/(.+)$~ ) {
			return [$basepath, $rtype, $rsid];
		}
	}
	return undef;
}

sub validate_session($$$$) {
	my ($req, $type, $vsid, $sess_opts) = @_;
	my $s = CGI::Session->load(ETVPN::Session::dsn, $vsid, $sess_opts) or
		return (undef, invalid_request($req, "error loading $type session $vsid: ".CGI::Session->errstr()));
	# generic session validations
	if ($s->is_empty()) {
		return (undef, invalid_request($req, "non-existing $type session $vsid requested"));
	}
	my $until_time = $s->param('until');
	if (!defined($until_time)) {
		return (undef, invalid_request($req, "invalid $type session requested (missing \"until\" value)", $s));
	}
	if ($until_time !~ /^\d{10,}$/) {
		return (undef, invalid_request($req, "invalid $type session requested (invalid \"until\" value \"$until_time\"", $s));
	}
	if ($until_time <= time()) {
		return (undef, invalid_request($req, "expired $type session requested", $s));
	}
	# type specific validations
	if ($type eq 'register') {
		if (defined($s->param('regdata'))) {
			return (undef, invalid_request($req, "attempted to access already registered session $vsid"));
		}
		foreach my $par ('auth id', 'account name', 'rp id', 'rp name') {
			if (!defined($s->param($par))) {
				return (undef, invalid_request($req, "invalid $type session requested (missing \"$par\" value)", $s));
			}
		}
	}
	elsif ($type eq 'authorize') {
		if (defined($s->param('reply'))) {
			return (undef, invalid_request($req, "attempted to access already replied authorization session $vsid"));
		}
		foreach my $par ('auth id', 'account name', 'user login', 'challenge', 'credential id', 'rp id', 'notify port') {
			if (!defined($s->param($par))) {
				return (undef, invalid_request($req, "invalid $type session requested (missing \"$par\" value)", $s));
			}
		}
	}
	else {
		# should not happen, since it was previously validated in request_params(), however be paranoid and ensure consistency
		return (undef, invalid_request($req, 'invalid request type', $s));
	}
	return ($s, undef);
}


##### Main
my $app = sub {
	my $env = shift;
	ETVPN::Web::translate_port_share($env);
	my $req = Plack::Request->new($env) or
		return invalid_request(undef, "Could not get a valid Plack::Request");

	# Check if session base path is defined
	my $session_base_dir = $ENV{'ETVPN_SESSION_BASE_DIR'} or
		return invalid_request($req, "ETVPN_SESSION_BASE_DIR not defined, please check your PSGI server configuration");

	# get request parameters
	my $req_par = request_params($env, $req);
	# confirm if parameters and request method are valid
	if (!$req_par || $req->method() !~ /(?:GET|POST)/) {
		my $req_uri = $req->request_uri();
		return invalid_request($req, 'invalid request attempted'.($req_uri ? ": $req_uri" : ''));
	};
	my ($basepath, $type, $sid) = @$req_par;
	# load and validate session
	# use different session subdirectory according to operation type
	my ($session, $err_reply) = validate_session($req, $type, $sid, { Directory => "$session_base_dir/$type" });
	return $err_reply if defined($err_reply);

	my $template = HTML::Template->new(filename => 'webauthn.tmpl', default_escape => 'html');
	$template->param(
		BASEPATH => $basepath,
		BODYCLASS => "body-$type",
	);

	my $response;
	if ($req->method() eq 'GET') {
		if ($type eq 'register') {
			# Send HTML/JS content with challenge and telling browser to ask for webauthn credentials
			my $challenge = random_bytes(32);
			$session->param('challenge' => $challenge);
			$session->flush() or return invalid_request($req, "register session $sid flush error when storing challenge: ".$session->errstr(), $session);
			$template->param(
				REGISTER => 1,
				TITLE => 'Registration',
				CHALLENGE => encode_json([ unpack('C*', $challenge) ]),
				RP_ID => $session->param('rp id'),
				RP_NAME => $session->param('rp name'),
				USER_ID => encode_json([ unpack('C*', $session->param('auth id')) ]),
				USER_NAME => $session->param('account name'),
				TIMEOUT => 60000, # TODO: fixed value atm, can't just be derived from "until"
			);
		}
		else {
			# authorize
			# For authorization the challenge is generated by the auth daemon and sent here via CGI session
			# This is by design so that the auth daemon can also validate the result and don't just trust an exposed CGI
			my $challenge = $session->param('challenge');
			my $credential_id = $session->param('credential id');
			$template->param(
				TITLE => 'Authorization',
				CHALLENGE => encode_json([ unpack('C*', $challenge) ]),
				RP_ID => $session->param('rp id'),
				CREDENTIAL_ID => encode_json([ unpack('C*', $credential_id) ]),
				TIMEOUT => 60000, # TODO: fixed value atm, can't just be derived from "until"
			);
		}
		$response = [200, ['Content-Type' => 'text/html; charset=utf8'], [$template->output]];
	}
	else {
		# POST - receive and validate data
		my $status = 400;  # Bad request unless validated
		my $result = 'INVALID';
		my $message = 'Invalid data received';
		my $submessage;
		my $reply;
		# Only accept if content type is the correct (important, or else body content won't be valid here)
		my $content_type = $req->headers->content_type;
		if (defined($content_type) &&
		    $content_type eq 'application/json' &&
		    $req->method eq 'POST' &&
		    do { $reply = eval { decode_json($req->content) }; !$@ }) {
			if ($type eq 'register') {
				my $challenge = $session->param('challenge') or return invalid_request($req, "missing challenge while processing reply for register session $sid", $session);
				if (defined($reply->{'data'}) && defined($reply->{'attestation'})) {
					my $uri = $req->uri();
					my $origin = URI->new($uri->scheme().'://'.$uri->authority())->canonical();
					$origin =~ s~/+$~~;
					my $webauthn_rp = Authen::WebAuthn->new(
						'rp_id'  => $session->param('rp id'),
						'origin' => $origin,
					);
					my $registration_result = eval {
						$webauthn_rp->validate_registration(
							challenge_b64 => encode_base64url($challenge, q{}),
							requested_uv => 'discouraged',
							client_data_json_b64   => $reply->{'data'},
							attestation_object_b64 => $reply->{'attestation'},
						);
					};
					if ($@) {
						logmsg($req, "error validating registration : $@");
					}
					else {
						$registration_result->{'when'} = time();
						$registration_result->{'credential_id'} = decode_base64url($registration_result->{'credential_id'});
						$registration_result->{'from'} = $req->address();
						$session->param('regdata' => $registration_result);
						if ($session->flush()) {
							$result = 'OK';
							$submessage = "Now please wait for your system administrator to approve the request.\r\nYou may close this window.";
							logmsg($req, "registration validated successfully and stored in session");
						}
						else {
							$result = 'ERROR';
							logmsg($req, "register session $sid flush error when storing user reply: ".$session->errstr());
						}
					}
				}
				else {
					logmsg($req, "invalid or incomplete reply data for registration session $sid (client might have tried to send a tampered response)");
				}
			}
			else {
				# authorize
				unless (defined($reply->{'data'}) && defined($reply->{'authenticator_data'}) &&
					defined($reply->{'signature'})) {
					logmsg($req, "invalid or incomplete reply data for authentication session $sid (client might have tried to send a tampered response)");
				}
				else {
					$session->param('reply' => $reply);
					if (!$session->flush()) {
						$result = 'ERROR';
						logmsg($req, "authorize session $sid flush error when storing user reply: ".$session->errstr());
					}
					else {
						# notify auth daemon and show response
						my $notify_h = IO::Socket::INET->new(
							PeerAddr => '127.0.0.1',
							PeerPort => $session->param('notify port'),
							Proto    => 'tcp',
							Type     => IO::Socket::SOCK_STREAM,
							Timeout  => 10
						);
						if (!$notify_h) {
							$result = 'ERROR';
							logmsg($req, "error connecting to auth daemon's notify port: $!");
						}
						else {
							# format: notify user_login cgi_remote_address auth_id
							print $notify_h 'notify '. $session->param('user login').' '.$req->address().' '.$session->param('auth id')."\n";
							my $server_reply = $notify_h->getline();
							$notify_h->close();
							($result, $submessage) = $server_reply =~ /^(\S+)\s+(.*)/;
							if ($result eq 'OK') {
								logmsg($req, "authentication session $sid successful");
							}
							elsif (!defined($result)) {
								$result = 'ERROR';
								logmsg($req, "authentication session $sid received empty reply from authentication daemon");
							}
							else {
								logmsg($req, "authentication session $sid received $result from authentication daemon");
							}
						}
					}
				}
			}
		}
		# Prepare status, log invalid or denied attempts
		if ($result eq 'OK') {
			$status = 200;  # OK
			$message = 'Success';
			$submessage = 'You may now close this window.' unless $submessage;
		}
		else {
			my $for_account_name = $session->param('account name') ? ' for user '.$session->param('account name') : '';
			if ($result eq 'DENIED') {
				$status = 403;  # Forbidden
				$message = 'Authentication failure';
				$submessage = "Please close this window and try again" unless $submessage;
				logmsg($req, "authentication failure$for_account_name");
			}
			elsif ($result eq 'NOTFOUND') {
				# in these conditions, invalid_request() sub generates the reply in JSON
				# reuse that functionality so that all "not found" errors are consistent
				# for this reason, any server submessage for 404 won't be shown, but can be logged
				return invalid_request(
					$req,
					"attempt to access invalid or expired auth session$for_account_name" . (
						$submessage ? " (server submessage: $submessage)" : ''
					),
					$session
				);
			}
			elsif ($result eq 'ERROR') {
				$status = 500;  # Internal server error
				$message = 'Server error';
				$submessage = "Please try again later" unless $submessage;
				logmsg($req, "reported server error$for_account_name");
			}
			else {
				$submessage = "Your browser sent invalid data, please ensure it is updated" unless $submessage;
				logmsg($req, "invalid authentication attempt$for_account_name");
			}
		}
		# Send JSON reply with result
		$response = json_reply($req, $status, $result, $message, $submessage)
	}

	return $response;
};
