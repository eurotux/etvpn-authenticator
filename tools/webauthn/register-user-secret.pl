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
use Bytes::Random::Secure;
use Digest::SHA qw(sha1);
use CGI::Session;
use POSIX qw(strftime);

use ETVPN::Cli;
use ETVPN::Conf;
use ETVPN::Session;
use ETVPN::Secret::RSA;
use ETVPN::COSE;

#################################
### Globals
#################################
$|=1;
my $conf;
my $realm;
my $username;
my $backend;

#### command line arguments
my $default_ini_file = '/etc/etvpn/etux-vpnserver.ini';
my $config_file = $default_ini_file;
my $command;
my $userlogin;
my $sid;
my @sids;
my $need_help = 0;


#######
# Subs and helpers
#######
sub help {
	print "Usage:\n";
	print "\t$0 [... options ...] <command> ...\n";
	print "\n";
	print "Commands:\n";
	print "\tnew <username>\n";
	print "\t\tCreate a new registration session for username and print the URL\n";
	print "\t\tPrompts for admin backend credentials (for backends that require them)\n";
	print "\tlist [username]\n";
	print "\t\tList pending not expired sessions for username and their status (if registered by the user and when)\n";
	print "\tshow <session_id>\n";
	print "\t\tShow details about a pending not expired session\n";
	print "\tapprove <username> <session_id>\n";
	print "\t\tApprove data from a user replied session and store it as the new user secret in the backend\n";
	print "\tdelete <session_id> [...session_id...]\n";
	print "\t\tDelete one or more sessions\n";
	print "\t\tPrompts for admin backend credentials (for backends that require them)\n";
	print "\n";
	print "Options:\n";
	print "\t-c|--config-file=FILE     Provide alternate configuration file. Default is $default_ini_file\n";
	print "\t-h|--help                 Show this help message.\n";
	print "\n";
	exit 1;
}

sub get_credentials() {
	my $backend_realm = $conf->get_username_backend_realm($userlogin) or ETVPN::Cli::die_error("Unknown realm for user $userlogin");
	($backend, $username, $realm) = @$backend_realm;
	# ensure sessions are always generated with user@realm format
	$userlogin = "$username\@$realm";
	if ($backend->need_admin_credentials()) {
		print "Need credentials for realm $realm\n";
		my $admin_username = ETVPN::Cli::read_prompt("Enter admin backend username: ");
		my $admin_password = ETVPN::Cli::read_prompt("Enter admin backend password: ", 1);
		$backend->connect_as($admin_username, $admin_password) or ETVPN::Cli::die_error($backend->get_error);
	}
}

sub sess_url($) {
	return $conf->val('url base').'/register/'.$_[0];
}

sub check_not_expired($$) {
	my ($session, $do_autoclean) = @_;
	return 0 if $session->is_empty;  # already cleaned session
	# check session sanity
	my $csid = $session->id();
	if (!defined($session->param('account name'))) {
		ETVPN::Cli::issue_warn("CRITICAL: session $csid is invalid and does not have an associated account name - DATA MAY HAVE BEEN TAMPERED");
		return -1;
	}
	if (!defined($session->param('account id'))) {
		ETVPN::Cli::issue_warn("CRITICAL: session $csid is invalid and does not have an associated account ID - DATA MAY HAVE BEEN TAMPERED");
		return -1;
	}
	# check if session has registration data and should be extended
	if (defined($session->param('regdata')) && !defined($session->param('in grace'))) {
		$session->param(
			'until' => $session->param('regdata')->{'when'} + $conf->val('registration approval grace'),
			'in grace' => 1
		);
	}
	my $until_time = $session->param('until');
	if (!defined($until_time) || $until_time <= time()) {
		if ($do_autoclean) {
			# clean expired session from disk
			my $account_name = $session->param('account name');
			$session->delete();
			if ($session->flush()) {
				ETVPN::Cli::issue_warn("Cleaned expired session $csid referring to user \"$account_name\"");
			}
			else {
				ETVPN::Cli::issue_warn("WARNING: found expired session $csid referring to user \"$account_name\ but there was an error while deleting it: ".$session->errstr());
			}
		}
		return 0;
	}
	return 1;
}

my @display_sessions;
sub filter_session($) {
	my $session = shift;
	if ( check_not_expired($session, 1) > 0 &&
	     ( !defined($userlogin) || $session->param('account name') eq $userlogin ) ) {
		push @display_sessions, $session;
	}
}

sub get_user_session($$$;$) {
	my ($usid, $sess_opts, $do_autoclean, $force_invalid) = @_;

	unless (defined($usid)) {
		# should never happen but for safety against coding errors
		ETVPN::Cli::die_error("Internal error in get_user_session, please contact support");
	}
	my $s = CGI::Session->load(ETVPN::Session::dsn, $usid, $sess_opts);
	my $session_status = check_not_expired($s, $do_autoclean);
	if ($session_status == 0) {
		ETVPN::Cli::die_error("session $usid not found");
	}
	if ($session_status < 0 && !$force_invalid) {
		ETVPN::Cli::die_error("session $usid is invalid");
	}
	if (defined($userlogin) && $s->param('account name') ne $userlogin) {
		ETVPN::Cli::die_error("session $usid does not refer to user \"$userlogin\"");
	}
	return $s;
}

sub isodate($) {
	return strftime('%Y-%m-%d %H:%M:%S', localtime($_[0]));
}

sub regdata_fields($) {
	my $s = shift;
	my ($rd, $registered, $from);
	if (defined( $rd = $s->param('regdata') )) {
		return (isodate($rd->{'when'}), $rd->{'from'});
	}
	return ('NO', '-');
}


###############
# Command Line
###############
my @cl_errors;
GetOptions (
	'h|help' => \$need_help,
	'c|config-file=s' => \$config_file,
) or push @cl_errors, "Invalid parameters.";
unless ( defined($command = shift @ARGV ) ) {
	push @cl_errors, "Missing command.";
}
else {
	my %valid_commands = map { $_ => 1 } (
		'new', 'list', 'show', 'approve', 'delete'
	);
	if (!exists($valid_commands{$command})) {
		push @cl_errors, "Invalid command: $command";
	}
	else {
		if ($command eq 'show') {
			$sid = shift @ARGV or push @cl_errors, "Missing session ID.";
		}
		elsif ($command eq 'delete') {
			@sids = @ARGV or push @cl_errors, "Missing session ID(s).";
		}
		else {
			$userlogin = shift @ARGV;
			if ($command ne 'list') {
				unless (defined($userlogin)) {
					push @cl_errors, "Missing username.";
				}
				elsif ($command eq 'approve') {
					unless ( defined( $sid = shift @ARGV ) ) {
						push @cl_errors, "Missing session_id.";
					}
				}
			}
		}
	}
}
if (@cl_errors) {
	print join("\n", @cl_errors)."\n\n";
	$need_help = 1;
}
help if $need_help;
$conf = ETVPN::Conf->new($config_file);

my $sess_opts = { Directory => $conf->val('cgi session directory base').'/register' };


###############
# Perform actions
###############
if ($command eq 'new') {
	get_credentials();
	my $login = $backend->get_user_login($username, $realm) or ETVPN::Cli::die_error($backend->has_internal_error() ? $backend->get_error() : "user \"$username\" does not exist or does not match realm \"$realm\" current backend criteria");
	print "Generating WebAuthn session for user $userlogin\n";
	$sid = ETVPN::Session::safe_session_name($sess_opts);
	my $saved_umask = umask;
	umask(0117);
	my $s = CGI::Session->new(ETVPN::Session::dsn, $sid, $sess_opts) or
		ETVPN::Cli::die_error("error creating new session: ".CGI::Session->errstr());
	my $account_name = $login->get_account_name() or ETVPN::Cli::die_error("invalid reply from backend: missing account name");
	my $account_id = $login->get_unique_id() or ETVPN::Cli::die_error("invalid reply from backend: missing account unique id");
	# CGI::Session expire method is relative to access time only, so it's not useful here; we have to implement another way
	my $salt = random_bytes(16);
	$s->param(
		'until' => time() + $conf->val('registration expiry'),
		# make auth id to be something consistent with user unique_id
		'auth id' => $salt.sha1("$salt$account_id"),
		'account name' => $userlogin,
		'account id' => $account_id,
		'rp id' => $conf->val('rp id'),
		'rp name' => $conf->val('rp name'),
	);
	my $flush_success = $s->flush();
	umask($saved_umask);
	ETVPN::Cli::die_error("FATAL: session flush error: ".$s->errstr()) unless $flush_success;
	print "URL: ".sess_url($sid)."\n";
}
elsif ($command eq 'list') {
	# fill @display_sessions array with valid sessions matching optional username
	CGI::Session->find(ETVPN::Session::dsn, \&filter_session, $sess_opts);
	# put extra line if warnings were issued, for better readability
	print "\n" if ETVPN::Cli::had_warning();
	if (@display_sessions) {
		ETVPN::Cli::output_table(
			[
			 ['Session', 'Account', 'Registered', 'Address', 'Valid Until'],
			 # sort by "until" date when listing
			 map {
				 my ($when, $from) = regdata_fields($_);
				 [ $_->id(), $_->param('account name'), $when, $from, isodate($_->param('until')) ] } sort { $a->param('until') <=> $b->param('until') } @display_sessions
			]
		);
	}
	else {
		print "No valid sessions found matching selected criteria.\n";
	}
}
elsif ($command eq 'show') {
	my $s = get_user_session($sid, $sess_opts, 1);
	my @show;
	push @show, ['Session ID', $s->id()];
	push @show, ['Account Name', $s->param('account name')];
	push @show, ['Auth ID', join('', unpack('(H2)*', $s->param('auth id')))];
	my ($when, $from) = regdata_fields($s);
	push @show, ['Registered', $when];
	push @show, ['Source Address', $from];
	my ($rd, $pk, $kd);
	if ( defined( $rd = $s->param('regdata') ) &&
	     defined( $pk = $rd->{'credential_pubkey'} ) ) {
		if (defined( $kd = ETVPN::COSE::base64url_pubkey_details($pk) ) ) {
			push @show, ['Key Status', 'PRESENT'];
			foreach my $kl (@$kd) {
				push @show, $kl;
			}
		}
		else {
			push @show, ['Key Status', 'INVALID'];
		}
	}
	else {
		push @show, ['Key Status', 'NOT PRESENT'];
	}
	push @show, ['In approval grace', defined($s->param('in grace')) ? 'YES' : 'NO'];
	push @show, ['Valid until', isodate($s->param('until'))];
	ETVPN::Cli::output_table(\@show, 4);
}
elsif ($command eq 'approve') {
	my $s = get_user_session($sid, $sess_opts, 1);
	if (!defined($s->param('regdata'))) {
		ETVPN::Cli::die_error("session $sid isn't yet registered by the user");
	}
	if (!defined($s->param('regdata')->{'credential_pubkey'}) ||
	    !defined(ETVPN::COSE::base64url_pubkey_details($s->param('regdata')->{'credential_pubkey'}))) {
		ETVPN::Cli::die_error("session $sid is invalid and does not have a credential public key");
	}
	get_credentials();
	my $login = $backend->get_user_login($username, $realm) or
		ETVPN::Cli::die_error("user $userlogin does not exist or does not match current backend criteria");
	if ($s->param('account name') ne $userlogin) {
		ETVPN::Cli::die_error("session $sid does not refer to user $userlogin");
	}
	do {
		no locale;
		if (($s->param('account id') cmp $login->get_unique_id()) != 0) {
			ETVPN::Cli::die_error("session $sid refers to a user with different unique id than the one on the backend, either it was issued for another user that was later renamed, or DATA MAY HAVE BEEN TAMPERED!")
		}
	};
	# Update user data in backend
	if ($backend->update_user_secret(new ETVPN::Secret::RSA($conf), 'webauthn', $username, $realm, $s->param('regdata'))) {
		print "Backend update successful\n";
		$backend->disconnect();
		$s->delete();
		$s->flush() or ETVPN::Cli::die_error("FATAL: flush error while trying to delete session: ".$s->errstr());
		print "Session $sid deleted\n";
	}
	else {
		ETVPN::Cli::die_error($backend->get_error);
	}
}
elsif ($command eq 'delete') {
	foreach my $dsid (@sids) {
		my $s = eval { get_user_session($dsid, $sess_opts, 0, 1) };
		if ($@) {
			ETVPN::Cli::issue_warn($@);
			next;
		}
		my $s_username = $s->param("account name");
		$s->delete();
		if ($s->flush()) {
			print "Session $dsid".(defined($s_username) ? " referring to user \"$s_username\"" : " without valid username")." deleted.\n";
		}
		else {
			ETVPN::Cli::issue_warn("CRITICAL: flush error while trying to delete session $dsid: ".$s->errstr());
		}
	}
}
else {
	# should not happen
	ETVPN::Cli::die_error("Internal error validating command, please contact support");
}


# TODO: send email to user?
