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

package ETVPN::Challenge::WebAuthn v0.7.3;
use strict;
use warnings;
use parent qw(ETVPN::Challenge::Base);
use List::Util 'pairs';
use CGI::Session;
use Bytes::Random::Secure;
use MIME::Base64 qw(encode_base64url);
use URI;
use Authen::WebAuthn;
use ETVPN::Session;


sub is_pending {
	#my ($self, $login) = @_;
	return 1;
}


sub _set_pending_webauthn_data {
	my $self = shift;

	my $pwa = $self->{'pending webauthn'};
	$pwa = $self->{'pending webauthn'} = {} unless defined($pwa);

	foreach my $kv (pairs @_) {
		$pwa->{$kv->[0]} = $kv->[1];
	}
}


sub _get_pending_webauthn_data {
	my ($self, $key) = @_;

	my $pwa = $self->{'pending webauthn'};
	$pwa = $self->{'pending webauthn'} = {} unless defined($pwa);

	# if a key is requested return its value
	# else conveniently return the hash reference for multiple value processing
	return defined($key) ? $pwa->{$key} : $pwa;
}


sub _has_pending_webauthn_data {
	my ($self, $key) = @_;

	my $pwa = $self->{'pending webauthn'};

	return defined($pwa) && exist($pwa->{$key});
}


sub _delete_web_session {
	my ($self, $web_session, $login) = @_;

	my $web_sid = $web_session->id();
	$web_session->delete();
	if ($web_session->flush()) {
		ETVPN::Logger::log("deleted webauthn session $web_sid");
	}
	else {
		ETVPN::Logger::log("WARNING: flush error when attempting to delete webauthn session $web_sid: ".$web_session->errstr());
	}
	my $pwa = $self->_get_pending_webauthn_data();

	my $current_web_sid = $pwa->{'web sid'};
	if (defined($current_web_sid) && $current_web_sid eq $web_sid) {
		delete $pwa->{'web sid'};
	}
}


sub DESTROY {
	my $self = shift;

	# clear web session if it exists
	my $pwa = $self->_get_pending_webauthn_data();
	if ( defined( my $web_sid = $pwa->{'web sid'} ) &&
	     defined( my $sess_opts = $pwa->{'sess opts'} ) ) {
		my $web_session = CGI::Session->load(ETVPN::Session::dsn, $web_sid, $sess_opts);
		unless ($web_session->is_empty()) {
			$self->_delete_web_session($web_session);
		}
	}
}


sub _generate_url {
	my ($self, $web_sid) = @_;

	return $self->get_conf()->val('url base')."/authorize/$web_sid";
}


sub is_crv {
	my ($self, $login) = @_;

	# use CR protocol when the client doesn't support openurl IV_SSO capability
	return !$login->has_iv_sso_capability('openurl');
}


sub is_crv_allowed_empty_reply {
	my ($self, $login) = @_;

	# we don't care about the CRV reply itself (what matters is if the webauthn authenticaition was performed)
	# so allow user just hitting ENTER
	return 1;
}


sub set_secret {
	my ($self, $login, $secret) = @_;

	# store secret for delayed validation
	$self->_set_pending_webauthn_data('regdata', $secret);
}


sub get_crv_prompt {
	my ($self, $login) = @_;

	if ( $self->is_crv($login) &&
	     defined( my $web_session = $self->_generate_webauth_session($login, $self->_get_pending_webauthn_data('regdata')) ) ) {
		# CR challenge phase 1
		my ($user_login, $auth_sid) = $login->get_auth_data();
		$web_session->param(
			'user login' => $user_login,
			'auth id' => $auth_sid,
		);
		$self->_set_pending_webauthn_data(
			'user login' => $user_login,
			'auth sid' => $auth_sid
		);
		return ('Please authorize at '.$self->_generate_url($web_session->id()).' and after that press ENTER here', 1);
	}
	# if reached here, either we're not in CRV compatibility mode, or there was an error creating/retrieving webauthn session
	# either way we must return undef
	return (undef, 0);
}


sub _generate_webauth_session {
	my ($self, $login, $secret) = @_;

	my $conf = $self->get_conf();
	my $sess_opts = { Directory => $conf->val('cgi session directory base').'/authorize' };

	if ( (my $existing_web_sid = $self->_get_pending_webauthn_data('web sid')) ) {
		my $until_time = _get_pending_webauthn_data('until time') or do {
			$self->add_internal_error("invalid webauthn challenge object when reusing session: missing expiry time");
			return undef;
		};
		if ($until_time <= time()) {
			$self->add_error("attempt to validate expired webauthn challenge");
			return undef;
		}
		my $existing_web_session = CGI::Session->load(ETVPN::Session::dsn, $existing_web_sid, $sess_opts);
		if ($existing_web_session->is_empty()) {
			$self->add_error("attempt to validate non-existing or expired webauthn challenge");
			return undef;
		}
		return $existing_web_session;
	}

	# generate new authorization session for the CGI
	my $web_sid = ETVPN::Session::safe_session_name($sess_opts);
	my $saved_umask = umask;
	umask(0117);
	my $web_session = CGI::Session->new(ETVPN::Session::dsn, $web_sid, $sess_opts);
	unless ($web_session) {
		$self->add_internal_error("error creating new webauthn session: ".CGI::Session->errstr());
		return undef;
	}
	# generate a challenge that we can also validate (we can't later fully trust the CGI since it's exposed)
	my $challenge = random_bytes(32);
	my $until_time = time() + $conf->val('auth expiry');
	my $account_name = $login->get_account_name();
	$web_session->param(
		'account name' => $account_name,
		'challenge' => $challenge,
		'credential id' => $secret->{'credential_id'},
		'rp id' => $conf->val('rp id'),
		'notify port' => $conf->val('notify port'),
		'until' => $until_time,
	);
	my $flush_success = $web_session->flush();
	umask($saved_umask);
	unless ($flush_success) {
		$self->add_internal_error("flush error when attempting to store new webauthn session data: ".$web_session->errstr());
		return undef;
	}
	ETVPN::Logger::log("created webauthn session $web_sid");
	# keep relevant data in memory so that any CGI session tampering attempt can later be detected and prevented
	$self->_set_pending_webauthn_data(
		'account name' => $account_name,
		'user unique id' => $login->get_unique_id(),
		'web sid' => $web_sid,
		'sess opts' => $sess_opts,
		'challenge' => $challenge,
		'until' => $until_time,
	);

	return $web_session;
}


sub _validate_webauthn_session {
	my ($self, $login, $regdata) = @_;

	my $pwa = $self->_get_pending_webauthn_data();

	# always perform checks to attempt to detect and prevent tampering
	my $web_sid = $pwa->{'web sid'} or do {
		$self->add_internal_error("invalid webauthn challenge object: missing web session");
		return 0;
	};
	my $sess_opts = $pwa->{'sess opts'} or do {
		$self->add_internal_error("invalid webauthn challenge object: missing web session options");
		return 0;
	};
	my $web_session = CGI::Session->load(ETVPN::Session::dsn, $web_sid, $sess_opts);
	if ($web_session->is_empty()) {
		$self->add_internal_error("invalid webauthn challenge object: attempted to reference an empty web session");
		return 0;
	}

	# keep on performing checks to attempt to detect and prevent tampering
	# mark some errors as internal so that IP is not banned because of possible bugs or our part
	my ($until_time, $reply, $reply_data, $reply_authenticator_data, $reply_signature, $challenge);

	if ( !($until_time = $pwa->{'until'}) ) {
		$self->add_internal_error("invalid webauthn challenge object: missing expiry time");
	}
	elsif ($until_time <= time()) {
		$self->add_error("attempt to validate expired webauthn challenge");
	}

	my ($check_user_login, $check_auth_sid) = $login->get_auth_data();
	my $auth_sid = $pwa->{'auth sid'};
	if (!defined($auth_sid)) {
		$self->add_internal_error("invalid webauthn challenge object: missing auth sid");
	}
	else {
		if ($auth_sid ne $check_auth_sid) {
			$self->add_internal_error("attempt to validate pending webauthn challenge with non corresponding auth sid");
		}
		if (!defined($web_session->param('auth id'))) {
			$self->add_error("invalid webauthn web session: missing auth id");
		}
		elsif ($auth_sid ne $web_session->param('auth id')) {
			$self->add_error("attempt to validate pending webauthn challenge from web session with different auth sid");
		}
	}

	my $account_name = $pwa->{'account name'};
	if (!defined($account_name)) {
		$self->add_internal_error("invalid webauthn challenge object: missing account name");
	}
	else {
		if ($account_name ne $login->get_account_name()) {
			$self->add_internal_error("attempt to validate pending webauthn challenge from login object with different account name");
		}
		if (!defined($web_session->param('account name'))) {
			$self->add_error("invalid webauthn web session: missing account name");
		}
		elsif ($account_name ne $web_session->param('account name')) {
			$self->add_error("attempt to validate pending webauthn challenge from web session with different account name");
		}
	}

	my $user_login = $pwa->{'user login'};
	if (!defined($user_login)) {
		$self->add_internal_error("invalid webauthn challenge object: missing user login");
	}
	else {
		if ($user_login ne $check_user_login) {
			$self->add_internal_error("attempt to validate pending webauthn challenge from login object with different user login");
		}
		if (!defined($web_session->param('user login'))) {
			$self->add_error("invalid webauthn web session: missing user login");
		}
		elsif ($user_login ne $web_session->param('user login')) {
			$self->add_error("attempt to validate pending webauthn challenge from web session with different user login");
		}
	}

	my $user_unique_id = $pwa->{'user unique id'};
	if (!defined($user_unique_id)) {
		$self->add_internal_error("invalid webauthn challenge object: missing user unique id");
	}
	elsif (do { no locale; ($user_unique_id cmp $login->get_unique_id()) != 0 }) {
		$self->add_internal_error("attempt to validate pending webauthn challenge from login object with different user unique id");
	}

	if ( !($reply = $web_session->param('reply')) ) {
		$self->add_error("invalid webauthn web session: missing reply");
	}
	else {
		if ( !($reply_data = $reply->{'data'}) ) {
			$self->add_error("empty webauthn data in client reply");
		}
		if ( !($reply_authenticator_data = $reply->{'authenticator_data'}) ) {
			$self->add_error("empty webauthn authenticator data in client reply");
		}
		if ( !($reply_signature = $reply->{'signature'}) ) {
			$self->add_error("empty webauthn signature in client reply");
		}
	}

	if ( !($challenge = $pwa->{'challenge'}) ) {
		$self->add_internal_error("invalid webauthn challenge object: missing one time challenge");
	}

	# prevent access and clean invalid related web session on errors
	if ($self->has_error()) {
		$self->_delete_web_session($web_session, $login);
		return 0;
	}

	my $conf = $self->get_conf();
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
			credential_pubkey_b64 => $regdata->{'credential_pubkey'},
			stored_sign_count => 0,
			requested_uv => 'discouraged',
			client_data_json_b64   => $reply_data,
			authenticator_data_b64 => $reply_authenticator_data,
			signature_b64 => $reply_signature,
			# we didn't call for any extensions on the request
			extension_results => {},
		);
	};
	if ($@) {
		# some internal errors can occur here, but most likely invalid data was sent by the browser
		# most likely provoked by a tampering attempt, so DON'T flag this as an internal error
		$self->add_error("error validating webauthn authorization : $@");
		return 0;
	}
	if ($validation_result) {
		ETVPN::Logger::log("webauthn authorization successful");
		$self->_set_pending_webauthn_data('cr_validated', 1) if $self->is_crv($login);
		return 1;
	}
	$self->add_error("webauthn authorization failed");
	return 0;
}


sub validate {
	my ($self, $login, $secret, $user_challenge_reply) = @_;

	if ($self->is_crv($login)) {
		# CR challenge phase 2 (client reconnected and user pressed enter on prompt)
		return $self->_get_pending_webauthn_data('cr_validated') ? 1 : 0;
	}
	else {
		# Pending challenge phase 1
		my $web_session = $self->_generate_webauth_session($login, $secret)
			or return 0;
		$self->_set_pending_webauthn_data('regdata' => $secret);
	}
	# Pending challenge phase 2 is only handled in validate_pending_auth
	return 0;
}


sub validate_pending_auth {
	my ($self, $login, $user_challenge_reply) = @_;

	if ($self->_get_pending_webauthn_data('cr_validated')) {
		$self->add_error('attempt to re-authenticate already authenticated CR webauthn challenge');
		return 0;
	}
	my $regdata = $self->_get_pending_webauthn_data('regdata');
	if (!defined($regdata)) {
		$self->add_internal_error("invalid webauthn challenge object: missing regdata");
		return 0;
	}

	return $self->_validate_webauthn_session($login, $regdata);
}


sub get_pending_string {
	my ($self, $login) = @_;

	# session should not be empty at this point, and pending webauthn data should exist in this object too
	# however if something is wrong in the code or any unforseen tampering has somehow ocurred, we want
	# to invalidate the auth session
	my $pwa = $self->_get_pending_webauthn_data();
	my $web_session = CGI::Session->load(ETVPN::Session::dsn, $pwa->{'web sid'}, $pwa->{'sess opts'});
	return undef if $web_session->is_empty();

	# user login is only set by auth daemon before calling this method, it wasn't available during the call to validate()
	# store user login and auth sid in CGI session so that the CGI can send back the notification
	my ($user_login, $auth_sid) = $login->get_auth_data();
	$web_session->param(
		'user login' => $user_login,
		'auth id' => $auth_sid,
	);
	# also store that information in this object for use when later performing anti-tamper validation
	$pwa->{'user login'} = $user_login;
	$pwa->{'auth sid'} = $auth_sid;

	# TODO: maybe someday add an option for the timeout in the following line (currently fixed at 60)
	return 'OPEN_URL:'.$self->_generate_url($pwa->{'web sid'}).' 60';
}


1;
