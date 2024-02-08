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
use Bytes::Random::Secure qw(random_bytes);
use MIME::Base64;
use Convert::Base32;
use URI::Escape;

use ETVPN::Cli;
use ETVPN::Conf;
use ETVPN::Secret::RSA;

#################################
### Globals
#################################
$|=1;
my $conf;
my $qrfile;
my $unlink_qr_file = 0;

#### command line arguments
my $default_ini_file = '/etc/etvpn/etux-vpnserver.ini';
my $config_file = $default_ini_file;
my $userlogin;
my $base32_secret;
my $verbatim_secret;
my $remove_secret = 0;
my $dry_run = 0;
my $need_help = 0;


#######
# Subs and helpers
#######
END {
	unlink $qrfile if defined($qrfile) && $qrfile ne '' && $unlink_qr_file;
}

sub help {
	print "Usage:\n";
	print "\t$0 [... options ...] username\n";
	print "\n";
	print "Options:\n";
	print "\t-c|--config-file=FILE     Provide alternate configuration file. Default is $default_ini_file\n";
	print "\t--base32-secret=SECRET    Optionally provide a fixed base32 secret. For migration purposes only, so NEVER\n";
	print "\t                          use this option otherwise as this tool normally generates a secure one\n";
	print "\t--verbatim-secret=SECRET  Optionally provide a fixed string secret. For migration purposes only, so NEVER\n";
	print "\t                          use this option otherwise as this tool normally generates a secure one\n";
	print "\t--remove-secret           Remove secret (disable OTP authentication for user)\n";
	print "\t                          Note that the user will be unable to login if MFA is enforced (see INI configuration)\n";
	print "\t                          or another secret (OTP or WebauthN) is configured for them\n";
	print "\t-d|--dry-run              Dry-run, generate a key when needed, show its values and QR code, but don't\n";
	print "\t                          actually try to update the user's field on the backend\n";
	print "\t-h|--help                 Show this help message.\n";
	print "\n";
	exit 1;
}


###############
# Command Line
###############
my @cl_errors;
GetOptions (
	'h|help' => \$need_help,
	'c|config-file=s' => \$config_file,
	'base32-secret=s' => \$base32_secret,
	'verbatim-secret=s' => \$verbatim_secret,
	'remove-secret' => \$remove_secret,
	'd|dry-run' => \$dry_run,
) or push @cl_errors, "Invalid parameters.";
unless ( defined($userlogin = shift @ARGV ) ) {
	push @cl_errors, "Missing username.";
}
if (defined($base32_secret) && defined($verbatim_secret)) {
	push @cl_errors, "Can't specify a base32-secret and a verbatim-secret at the same time.";
}
if ( ( defined($base32_secret) || defined($verbatim_secret) ) && $remove_secret ) {
	push @cl_errors, "Can't specify a base32-secret or a verbatim-secret and attempt to remove at the same time.";
}

if (@cl_errors) {
	print join("\n", @cl_errors)."\n\n";
	$need_help = 1;
}
help if $need_help;
$conf = ETVPN::Conf->new($config_file);

my $backend_realm = $conf->get_username_backend_realm($userlogin) or ETVPN::Cli::die_error("Unknown realm for user $userlogin");
my ($backend, $uname, $realm) = @$backend_realm;
print "Updating user $uname on realm $realm\n";

###############
# Perform actions
###############
my $secret;
my $secret_b32;
my $otp_url;
my $shown;
unless ($remove_secret) {
	if (defined($base32_secret)) {
		# check if command line given base32 secret is valid
		$secret = eval { decode_base32($base32_secret) };
		ETVPN::Cli::die_error("Invalid (non-base32) provided secret.") if $@;
		my @secret_bytes = unpack('C*', $secret);
		if (@secret_bytes < 16) {
			warn "\nWARNING: provided verbatim secret is INSECURE: RFC-4226 states minimum of 128 bit (16 bytes) long, recommends at least 160 bit (20 bytes)\n\n";
		}
		$secret_b32 = uc($base32_secret);
	}
	elsif (defined($verbatim_secret)) {
		# check if command line given verbatim secret is valid
		if (length($verbatim_secret) < 10) {
			warn "\nWARNING: provided verbatim secret is INSECURE: RFC-4226 states minimum of 128 bit (16 bytes) long, recommends at least 160 bit (20 bytes)\n\n";
		}
		$secret = $verbatim_secret;
		$secret_b32 = uc(encode_base32($verbatim_secret));
	}
	else {
		# Generate otpauth secret - RFC-4226 recomends a shared secret length of 160 bits (20 bytes)
		$secret = random_bytes(20);
		$secret_b32 = uc(encode_base32($secret));
	}
	$otp_url = sprintf "otpauth://totp/%s?secret=%s&digits=%u&issuer=%s", uri_escape($conf->val('otpauth label').":$uname\@$realm"), uri_escape($secret_b32), $conf->val('otpauth digits'), uri_escape($conf->val('otpauth issuer'));

	# Generate QR code
	$shown = 0;
	if ($conf->isdef('qrencoder')) {
		$qrfile = `mktemp --suffix=.png`;
		if ($? != 0) {
			ETVPN::Cli::die_error("Could not create temporary file, aborting", $? >> 8);
		}
		chomp $qrfile;
		$unlink_qr_file = 1;

		system($conf->val('qrencoder'), '-s', 6, '-t', 'PNG', '-o', $qrfile, $otp_url);
		if ($? != 0) {
			ETVPN::Cli::die_error("Could not generate QR code, aborting");
		}
		$shown = 1;
	}
}

# Update user data in backend
unless ($dry_run) {
	if ($backend->need_admin_credentials()) {
		print "Need credentials for realm $realm\n";
		my $admin_username = ETVPN::Cli::read_prompt("Enter admin backend username: ");
		my $admin_password = ETVPN::Cli::read_prompt("Enter admin backend password: ", 1);
		$backend->connect_as($admin_username, $admin_password) or ETVPN::Cli::die_error($backend->get_error);
	}

	my $result_ok;
	if ($remove_secret) {
		$result_ok = $backend->remove_user_secret($uname, $realm);
	}
	else {
		$result_ok = $backend->update_user_secret(new ETVPN::Secret::RSA($conf), 'otpauth', $uname, $realm, $secret);
	}

	if ($result_ok) {
		print "Update successful\n";
		$backend->disconnect();
	}
	else {
		ETVPN::Cli::die_error($backend->get_error);
	}
}

if ($remove_secret) {
	# We're done
	exit 0;
}

# Show QR code
if ($conf->isdef('qrviewer')) {
	system($conf->val('qrviewer'), $otp_url);
	$shown = 1;
}
if ($qrfile) {
	$unlink_qr_file = 0;
	if ($conf->isdef('pngviewer')) {
		system($conf->val('pngviewer'), $qrfile);
	}
}

# TODO: send email to user?

print "Wrote QR code to $qrfile - PLEASE REMOVE IT WHEN FINISHED\n\n" if $qrfile;

# As a last resort if nothing was done to save or show the code, print it
print "TOTP url: $otp_url\n" unless $shown;
