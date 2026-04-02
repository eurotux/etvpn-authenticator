#!/usr/bin/perl -w
# ETVPN Authenticator - Basic integration tests
# Copyright (C) 2023 Eurotux Informatica S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Basename;
use Cwd qw(realpath);

my $srcdir = realpath(dirname($0).'/..');
my $passed = 0;
my $failed = 0;
my $total = 0;
my @failure_details;
my $last_tool_output = '';

sub run_test {
	my ($name, $sub) = @_;
	$total++;
	$last_tool_output = '';
	print "  TEST $total: $name ... ";
	my $result = eval { $sub->() };
	if ($@ || !$result) {
		$failed++;
		print "FAILED\n";
		my $detail = $@ || $last_tool_output || '';
		chomp $detail;
		push @failure_details, "  TEST $total: $name\n    $detail" if $detail;
		return 0;
	}
	$passed++;
	print "OK\n";
	return 1;
}

sub perl_syntax_check {
	my ($script) = @_;
	local $ENV{PERLLIB} = "$srcdir/lib";
	my $pid = open(my $rd, '-|') // return (1, "failed to fork: $!");
	if ($pid == 0) {
		$| = 1;
		open(STDERR, '>&', STDOUT);
		exec($^X, '-c', "$srcdir/$script");
		die "exec failed: $!";
	}
	local $/;
	my $output = <$rd>;
	close $rd;
	my $rc = $? >> 8;
	$output = defined($output) ? $output : '';
	$last_tool_output = $output;
	return ($rc, $output);
}

sub run_tool {
	my ($tool, @args) = @_;
	local $ENV{PERLLIB} = "$srcdir/lib";
	my $pid = open(my $rd, '-|') // return (1, "failed to fork: $!");
	if ($pid == 0) {
		$| = 1;
		open(STDERR, '>&', STDOUT);
		exec($^X, "$srcdir/$tool", @args);
		die "exec failed: $!";
	}
	local $/;
	my $output = <$rd>;
	close $rd;
	my $rc = $? >> 8;
	$output = defined($output) ? $output : '';
	$last_tool_output = $output;
	return ($rc, $output);
}

sub run_tool_stdin {
	my ($stdin_data, $tool, @args) = @_;
	local $ENV{PERLLIB} = "$srcdir/lib";
	require IPC::Open2;
	my $pid = IPC::Open2::open2(my $rd, my $wr, $^X, "$srcdir/$tool", @args);
	print $wr $stdin_data;
	close $wr;
	local $/;
	my $output = <$rd>;
	close $rd;
	waitpid($pid, 0);
	my $rc = $? >> 8;
	$output = defined($output) ? $output : '';
	$last_tool_output = $output;
	return ($rc, $output);
}


#################################
# Setup temporary test environment
#################################
print "Setting up test environment...\n";
my $tmpdir = tempdir('etvpn-test-XXXXXX', TMPDIR => 1, CLEANUP => 1);
my $dbfile = "$tmpdir/test.db";
my $inifile = "$tmpdir/test.ini";
my $privkey = "$tmpdir/test-rsa.key";
my $pubkey = "$tmpdir/test-rsa-public.key";

# Generate RSA keys
my ($rc, $out) = run_tool("tools/rsa/create-master-key.pl", $privkey, $pubkey);
die "Failed to generate RSA keys: $out" if $rc != 0;

# Create SQLite database with full schema
system("sqlite3", $dbfile, <<'SQL') == 0 or die "Failed to create test database";
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL, challenge TEXT, ipv4_address TEXT, ipv6_address TEXT, ipv4_routes TEXT, ipv6_routes TEXT);
CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, ipv4_routes TEXT, ipv6_routes TEXT);
CREATE TABLE users_groups (user_id INTEGER NOT NULL, group_id INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE, FOREIGN KEY (group_id) REFERENCES groups(id) ON UPDATE CASCADE ON DELETE CASCADE, PRIMARY KEY (user_id, group_id));
CREATE TABLE subgroups (parent_id INTEGER NOT NULL, child_id INTEGER NOT NULL, FOREIGN KEY (parent_id) REFERENCES groups(id) ON UPDATE CASCADE ON DELETE CASCADE, FOREIGN KEY (child_id) REFERENCES groups(id) ON UPDATE CASCADE ON DELETE CASCADE, PRIMARY KEY (parent_id, child_id));
SQL

# Determine a valid system group for psgi group config
my $test_gid = (stat($0))[5];
my $test_group = (getgrgid($test_gid))[0] || 'nogroup';

# Create cgi session directories for config validation
my $cgi_sessions = "$tmpdir/cgi-sessions";
mkdir $cgi_sessions, 0700 or die "Cannot create $cgi_sessions: $!";
foreach my $subdir ("$cgi_sessions/register", "$cgi_sessions/authorize") {
	mkdir $subdir or die "Cannot create $subdir: $!";
	chown -1, $test_gid, $subdir;
	chmod 02770, $subdir;
}

# Write minimal test INI
open(my $fh, '>', $inifile) or die "Cannot write $inifile: $!";
print $fh <<EOF;
[global]
management interface address = 127.0.0.1
management interface port = 1
management interface password = test
default backend = testdb
ssl key = $privkey
otpauth label = test
otpauth issuer = test
url base = https://127.0.0.1/
psgi group = $test_group
cgi session directory base = $cgi_sessions

[backend testdb sql]
enabled = true
driver = SQLite
database parameters = dbname=$dbfile
users col ipv4 address = ipv4_address
users col ipv6 address = ipv6_address
users col ipv4 routes = ipv4_routes
users col ipv6 routes = ipv6_routes
groups table = groups
groups col ipv4 routes = ipv4_routes
groups col ipv6 routes = ipv6_routes
EOF
close $fh;

my $manage = "tools/sql/manage_sql_userdb.pl";
my $show_user = "tools/generic/show_user.pl";
my @cli_opts = ("-c", $inifile);

print "Test environment ready at $tmpdir\n\n";


#################################
# Test: Syntax check
#################################
print "=== Syntax checks ===\n";

run_test("daemon syntax check", sub {
	my ($rc, $out) = perl_syntax_check("daemon/etux-vpnserver-auth.pl");
	return $out =~ /syntax OK/ && $out !~ /\bWARNING\b/i;
});

run_test("manage_sql_userdb.pl syntax check", sub {
	my ($rc, $out) = perl_syntax_check($manage);
	return $out =~ /syntax OK/;
});

run_test("show_user.pl syntax check", sub {
	my ($rc, $out) = perl_syntax_check($show_user);
	return $out =~ /syntax OK/;
});


#################################
# Test: User and group management
#################################
print "\n=== User and group management ===\n";

run_test("useradd with password", sub {
	my ($rc, $out) = run_tool_stdin("TestPass1!\nTestPass1!\n", $manage, @cli_opts, "useradd", 'testuser@testdb');
	return $rc == 0;
});

run_test("usermod --add-ipv4-route", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usermod", 'testuser@testdb', "--add-ipv4-route=10.99.0.0/24");
	return $rc == 0;
});

run_test("usershow displays IPv4 route", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usershow", 'testuser@testdb');
	return $rc == 0 && $out =~ /10\.99\.0\.0\/24/;
});

run_test("usermod --remove-ipv4-route", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usermod", 'testuser@testdb', "--remove-ipv4-route=10.99.0.0/24");
	return $rc == 0;
});

run_test("usershow after remove shows dash", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usershow", 'testuser@testdb');
	return $rc == 0 && $out =~ /IPv4 Routes\s+-/;
});

run_test("groupadd", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "groupadd", 'testgroup@testdb');
	return $rc == 0;
});

run_test("groupmod --add-ipv4-route", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "groupmod", 'testgroup@testdb', "--add-ipv4-route=172.16.0.0/12");
	return $rc == 0;
});

run_test("groupshow displays IPv4 route", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "groupshow", 'testgroup@testdb');
	return $rc == 0 && $out =~ /172\.16\.0\.0\/12/;
});

run_test("assign user to group", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usermod", 'testuser@testdb', "--add-to-group=testgroup");
	return $rc == 0;
});


#################################
# Test: show_user.pl computed routes
#################################
print "\n=== show_user.pl computed routes ===\n";

run_test("setup: add IPv4 route to user", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usermod", 'testuser@testdb', "--add-ipv4-route=10.99.0.0/24");
	return $rc == 0;
});

run_test("show_user.pl displays user and group routes", sub {
	my ($rc, $out) = run_tool($show_user, @cli_opts, 'testuser@testdb');
	return $rc == 0 && $out =~ /10\.99\.0\.0\/24/ && $out =~ /172\.16\.0\.0\/12/ && $out =~ /Computed Push Routes/;
});


#################################
# Test: Conflicting options
#################################
print "\n=== Conflicting options ===\n";

run_test("--no-ipv4-routes and --add-ipv4-route conflict", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usermod", 'testuser@testdb', "--no-ipv4-routes", "--add-ipv4-route=10.0.0.0/8");
	return $rc != 0 && $out =~ /Conflicting/;
});

run_test("--no-ipv6-routes and --add-ipv6-route conflict", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usermod", 'testuser@testdb', "--no-ipv6-routes", "--add-ipv6-route=fd00::/64");
	return $rc != 0 && $out =~ /Conflicting/;
});


#################################
# Test: Option context validation
#################################
print "\n=== Option context validation ===\n";

run_test("IP route options rejected on usershow", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "usershow", 'testuser@testdb', "--add-ipv4-route=10.0.0.0/8");
	return $rc != 0 && $out =~ /not valid in this context/;
});

run_test("IP address options rejected on passwd", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "passwd", 'testuser@testdb', "--ipv4-address=10.0.0.1");
	return $rc != 0 && $out =~ /not valid in this context/;
});

run_test("group membership options rejected on groupshow", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "groupshow", 'testgroup@testdb', "--no-groups");
	return $rc != 0 && $out =~ /not valid in this context/;
});

run_test("IP route options rejected on userdel", sub {
	my ($rc, $out) = run_tool($manage, @cli_opts, "userdel", 'testuser@testdb', "--add-ipv4-route=10.0.0.0/8");
	return $rc != 0 && $out =~ /not valid in this context/;
});


#################################
# Summary
#################################
print "\n" . "=" x 40 . "\n";
print "Results: $passed passed, $failed failed, $total total\n";
print "=" x 40 . "\n";
if (@failure_details) {
	print "\nFailure details:\n";
	foreach my $detail (@failure_details) {
		print "$detail\n\n";
	}
}
exit($failed > 0 ? 1 : 0);
