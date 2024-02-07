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

package ETVPN::Conf v0.7.4;
use strict;
use warnings;
use File::stat;
use Cwd 'abs_path';
use File::Basename;
use File::Path 'make_path';
use File::Temp 'tempfile';
use Fcntl "S_ISDIR";
use Config::IniFiles;
use Net::IP;
use URI;
use ETVPN::Logger;
use ETVPN::IPPool;
use ETVPN::Backend;
use ETVPN::Util;


my %conf_structure = (
	'global' => [
		'management interface address',
		'management interface port',
		'management interface password',
		['notify port', def => 5194],
		['management interface retry', def => 5, min => 5, type => 'uint'],
		['management interface connect timeout', def => 20, min => 1, type => 'uint'],
		['default backend', def => ''],
		['enforce mfa', def => 1, type => 'bool'],
		['challenge session timeout', def => 60, min => 20, max => 120, type => 'uint'],
		['secret encryption type', def => 'RSA'],
		'ssl key',
		['url base', transform => \&__transform_chomp_trailing_slashes],
		['rp id', def => ''],  # if not given, will later be set to base url host part
		['rp name', def => 'ETVPN'],
		['psgi group', def => 'etvpnwww'],
		['registration expiry', def => 172800, min => 1, type => 'uint'],
		['registration approval grace', def => 1209600, min => 1, type => 'uint'],
		['auth expiry', def => 120, min => 1, type => 'uint'],
		['cgi session directory base', def => '/var/lib/etvpn/cgi-sessions', transform => \&__transform_chomp_trailing_slashes],
		['oathtool', def => '/usr/bin/oathtool'],
		'otpauth label',
		'otpauth issuer',
		['otpauth digits', def => 6, type => 'uint'],
		['otpauth tolerance', def => 10, type => 'uint'],
		['qrencoder', def => ''],
		['pngviewer', def => ''],
		['qrviewer', def => ''],
	],
	'ippool' => [
		'driver',
		'database parameters',
		['database username', def => ''],
		['database password', def => ''],
	],
	'backend' => [
		['auth append realm', def => 0, type => 'bool'],
		['realm aliases', list => 1, def => []],
	],
	# TODO: move backend specific validations to the backend classes?
	'backend ldap' => [
		['ldap address', list => 1],
		'ldap base',
		'ldap group',
		['ldap timeout', def => 10, min => 1, type => 'uint'],
		'ldap login filter',
		'ldap dn filter',
		['ldap bind dn format', def => ''],
		['ldap bind dn', def => ''],
		['ldap bind password', def => ''],
		['ldap challenge field', def => ''],
		['ldap unique identifier', def => ''],
		['ldap account name', def => ''],
		['ldap group membership filter', def => ''],
		['ldap ipv4 static address', def => ''],
		['ldap ipv4 static address format', def => 'text'],
		['ldap ipv6 static address', def => ''],
		['ldap ipv6 static address interface id', def => ''],
		['ldap ipv4 routes', def => ''],
		['ldap ipv6 routes', def => ''],
		['ldap ip routes', def => ''],
	],
	'backend sql' => [
		'driver',
		'database parameters',
		['database username', def => ''],
		['database password', def => ''],
		['need admin credentials', def => 0],
		['users table', def => 'users'],
		['users col id', def => 'id'],
		['users col name', def => 'name'],
		['users col password', def => 'password'],
		['users col challenge', def => 'challenge'],
		['users col ipv4 address', def => ''],
		['users col ipv6 address', def => ''],
		['users col ipv4 routes', def => ''],
		['users col ipv6 routes', def => ''],
		['users allow same fixed ip address', def => 0, type => 'bool'],
		['groups table', def => ''],
		['groups col id', def => 'id'],
		['groups col name', def => 'name'],
		['groups col ipv4 routes', def => ''],
		['groups col ipv6 routes', def => ''],
		['users groups relation table', def => 'users_groups'],
		['users groups user id', def => 'user_id'],
		['users groups group id', def => 'group_id'],
		['subgroups relation table', def => 'subgroups'],
		['subgroups parent id', def => 'parent_id'],
		['subgroups child id', def => 'child_id'],
	],
);

my %extra_validations = (
	# LDAP specific
	'backend ldap' => sub {
		my $conf = shift;
		if ($conf->anydef('ldap bind dn', 'ldap bind password') &&
		    !$conf->isdef('ldap bind dn', 'ldap bind password', 'ldap dn filter')) {
			confdie("'ldap bind dn', 'ldap bind password' and 'ldap dn filter' must all be defined if at least one is defined");
		}
		if ($conf->is_true('enforce mfa') && !$conf->isdef('ldap challenge field')) {
			confdie("'ldap challenge field' is mandatory when 'enforce mfa' is true");
		}
		if ($conf->isdef('ldap challenge field') && !$conf->isdef('ldap unique identifier', 'ldap account name')) {
			confdie("'ldap unique identifier' and 'ldap account name' are mandatory when 'ldap challenge field' is set");
		}
		if ($conf->val('ldap ipv4 static address format') !~ /^(int|text)$/) {
			confdie("'ldap ipv4 static address format' must be either 'int' or 'text'");
		}
	},
);


sub confdie($) {
	ETVPN::Logger::fatal_code(99, "Configuration error: ".$_[0]);
}


sub new {
	my ($class, $config_file, $read_only) = @_;

	my $self = bless {}, $class;
	$self->set('read_only', $read_only);
	$self->_load_main_config($config_file);

	return $self;
}


sub new_subconf {
	my ($class, $parent_params) = @_;

	my $data = $parent_params ? $parent_params : {};
	my $self = bless $data, $class;

	return $self;
}


sub val {
	my ($self, $key) = @_;
	return $self->{$key};
}


sub is_true {
	my ($self, $key) = @_;
	return $self->{$key} ? 1 : 0;
}


sub valcmp {
	my ($self, $key, $value) = @_;
	return $self->{$key} cmp $value;
}


sub set {
	my ($self, $key, $value) = @_;
	$self->{$key} = $value;
	return $value;
}


sub anydef {
	my ($self, @keys) = @_;
	foreach my $key (@keys) {
		return 1 if exists($self->{$key}) && $self->{$key} ne '';
	}
	return 0;
}


sub isdef {
	my ($self, @keys) = @_;
	foreach my $key (@keys) {
		return 0 if !exists($self->{$key}) || $self->{$key} eq '';
	}
	return 1;
}


sub add_routes {
	my ($self, $routes) = @_;
	$self->{'push routes'} = ETVPN::Util::add_new_routes($self->{'push routes'}, $routes);
}


sub add_group_routes {
	my ($self, $group, $routes) = @_;
	my $prg = $self->{'push routes group'};
	unless (defined($prg)) {
		$prg = $self->{'push routes group'} = {};
	}
	$prg->{$group} = ETVPN::Util::add_new_routes($prg->{$group}, $routes);
}


sub get_routes {
	my $self = shift;
	$self->{'push routes'} = {} unless defined($self->{'push routes'});
	return $self->{'push routes'};
}


sub get_group_routes {
	my $self = shift;
	$self->{'push routes group'} = {} unless exists($self->{'push routes group'});
	return $self->{'push routes group'};
}


sub set_group_ip_pool {
	my ($self, $group, $ip_pool, $ipver) = @_;
	my $key = "ipv$ipver pool group";
	my $ipg = $self->{$key};
	unless (defined($ipg)) {
		$ipg = $self->{$key} = {};
	}
	my $ip = new Net::IP($ip_pool, $ipver) or confdie("invalid IPv$ipver pool: $ip_pool");
	confdie("can't use IPv$ipver pool $ip_pool: each IP pool must be able to hold at least 6 addresses") if $ip->size() < 6;
	foreach my $og (keys(%$ipg)) {
		my $oip = $ipg->{$og};
		confdie("IP pool $ip_pool for group $group conflicts with IP pool ".$oip->print()." from group $og") if $oip->overlaps($ip) != $IP_NO_OVERLAP;
	}
	$ipg->{$group} = $ip;
}


sub get_group_ip_pools {
	my ($self, $ipver) = @_;
	my $key = "ipv$ipver pool group";
	$self->{$key} = {} unless exists($self->{$key});
	return $self->{$key};
}


sub get_ip_pool {
	my $self = shift;
	return $self->{'ippool'};
}


sub get_backend {
	my ($self, $realm) = @_;

	if (!defined($realm)) {
		if ($self->isdef('default backend')) {
			$realm = $self->val('default backend');
		}
		else {
			return undef;
		}
	}
	return $self->val('backends')->{$realm};
}


sub get_username_backend_realm {
	my ($self, $user_name) = @_;

	my ($name, $realm);
	# support domain\user and user@domain login formats
	if ( !( ($name, $realm) = $user_name =~ /^([^@\\]+)@([^@\\\n]+)/ ) &&
	     !( ($realm, $name) = $user_name =~ /^([^@\\]+)\\([^@\\\n]+)/ ) ) {
		if ( $self->isdef('default backend') && $user_name !~ /[@\\\n]/ ) {
			$name = $user_name;
			$realm = $self->val('default backend');
		}
	}
	return undef unless (defined($name) && defined($realm));
	my $backend = $self->val('backends')->{$realm} or return undef;
	return [$backend, $name, $realm];
}


sub reload {
	my ($self, $config_file) = @_;

	# To revert to previous config on failure
	my $prev_conf = { %$self };

	%$self = ();
	eval {
		$self->_load_main_config($config_file);
	};

	my @errors;
	if ($@) {
		# Errors found, revert
		ETVPN::Logger::log($@);
		%$self = %$prev_conf;
		ETVPN::Logger::log("Reload failed, reverted to previous in-memory configuration");
	}
}


sub __transform_chomp_trailing_slashes($) {
	my $s = shift;
	$s =~ s~/+$~~;
	return $s;
}


sub load_ini_config {
	my $config_file = shift;

	my $st = stat($config_file) or confdie("can't stat config file $config_file: $!");
	if ($st->mode & 0137 != 0640) {
		confdie("cannot load configuration from file \"$config_file\" because of insecure permissions (can't be world accessible, can't be group writeable)");
	}

	return Config::IniFiles->new( -file => $config_file, @_ );
}


sub _load_main_config {
	my ($self, $config_file) = @_;

	$self->_assert_configuration($config_file);

	## Extra validations
	if ($self->isdef('default backend')) {
		my $def_backend = $self->val('default backend');
		confdie("unknown default backend \"$def_backend\"") unless exists($self->val('backends')->{$def_backend});
	}

	# WebAuthn specific
	my $uri_base = URI->new($self->val('url base'));
	my $uri_base_host;
	unless ( defined($uri_base) && ( $uri_base_host = $uri_base->host ) ) {
		confdie("invalid url base \"".$self->val('url base').'"');
	}
	unless ($self->isdef('rp id')) {
		$self->set('rp id', $uri_base_host);
	}
	# Following validations are not to be performed if read_only flag is set (used by sqluserportal daemon)
	return if $self->val('read_only');
	my $psgi_gid = getgrnam($self->val('psgi group')) or
		confdie("invalid or non existing group \"".$self->val('psgi group').'"');
	my $cgi_st = stat($self->val('cgi session directory base')) or
		confdie("can't stat cgi session directory ".$self->val('cgi session directory base').": $!");
	if (!S_ISDIR($cgi_st->mode)) {
		confdie('"'.$self->val('cgi session directory base').'" is not a directory');
	}
	if ($cgi_st->mode & 0027) {
		confdie("refusing to use session directory base with insecure permissions - can't be group writable nor world accessible - REGISTRATION AND ACCESSES MAY HAVE BEEN COMPROMISED!");
	}
	foreach my $subdir ('register', 'authorize') {
		my $full_subdir = $self->val('cgi session directory base')."/$subdir";
		my $sub_st = stat($full_subdir);
		if ($sub_st) {
			if (!S_ISDIR($sub_st->mode)) {
				confdie("'$full_subdir' already exists but is not a directory");
			}
			if (($sub_st->mode & 07777) != 02770 || $sub_st->gid != $psgi_gid ) {
				confdie("refusing to use session subdirectory '$full_subdir' with inadequate permissions - must be 02770 and same group as the psgi server - REGISTRATION AND ACCESSES MAY HAVE BEEN COMPROMISED!");
			}
			my ($test_fh, $test_filename) = eval { tempfile('etvpn_test_XXXXXX', DIR => $full_subdir) };
			if ($@) {
				confdie("can't write to session subdirectory '$full_subdir', please ensure it has the correct ownership: $@");
			}
			close $test_fh;
			unlink $test_filename
		}
		else {
			# create session subdirectory with adequate mode and ownership
			make_path($full_subdir, { 'mode' => 0751, 'group' => $psgi_gid, 'error' => \my $err });
			if ($err && @$err) {
				 my ($file, $message) = %{$err->[0]};
				confdie("could not create '$full_subdir' with mode 0751 and group '".$self->val('psgi group')."' (error: $message); please create it beforehand");
			}
		}
	}
}


sub __is_section_enabled($$) {
	my ($cfg, $section) = @_;

	return get_mandatory_in_range($cfg, $section, 'enabled', 'bool', 0);
}


sub _assert_section {
	my ($self, $cfg, $section, $ignore_enabled, @structure_keys) = @_;

	my %left_params = map { $_ => 1 } $cfg->Parameters($section);
	foreach my $sk (@structure_keys) {
		foreach my $item (@{$conf_structure{$sk}}) {
			my ($key, $value);
			if (ref($item)) {
				my ($name, %params) = @$item;
				$key = $name;
				if (defined($params{'type'})) {
					$value = get_mandatory_in_range($cfg, $section, $name, $params{'type'}, $params{'def'}, $params{'min'}, $params{'max'});
				}
				else {
					$value = get_mandatory($cfg, $section, $name, $params{'def'}, $params{'list'}, !$params{'no_split'});
				}
				# apply transformation routine
				if (defined($params{'transform'})) {
					$value = &{$params{'transform'}}($value);
				}
			}
			else {
				$value = get_mandatory($cfg, $section, $item);
				$key = $item;
			}
			$self->set($key, $value);
			delete $left_params{$key};
		}
	}
	delete $left_params{'enabled'} if $ignore_enabled;
	# Handle special parameters
	foreach my $name (keys %left_params) {
		if ($name eq 'push routes') {
			$self->add_routes(get_mandatory($cfg, $section, $name, undef, 1, 1));
			delete $left_params{$name};
		}
		elsif ($name =~ /^push routes group (.+)/) {
			$self->add_group_routes($1, get_mandatory($cfg, $section, $name, undef, 1, 1));
			delete $left_params{$name};
		}
		elsif ($name =~ /^ipv4 pool group (.+)/) {
			confdie("IP pool group assignments aren't valid without a [ippool] section") unless $self->isdef('ippool');
			$self->set_group_ip_pool($1, get_mandatory($cfg, $section, $name), 4);
			delete $left_params{$name};
		}
	}
	my @unknown = keys(%left_params);
	confdie('invalid parameter'.(@unknown == 1 ? '' : 's')." in section [$section]: ".join(', ', @unknown)) if @unknown;
}


sub _assert_configuration {
	my ($self, $config_file) = @_;

	my $cfg = load_ini_config($config_file) or confdie("Error(s) found getting settings from $config_file" .(@Config::IniFiles::errors ? ': '.join("\n", @Config::IniFiles::errors) : ''));

	unless ($cfg->SectionExists('global')) {
		confdie("configuration section [global] not found");
	}
	# Include subfiles if "include" option exists in section [global]
	my $includes = get_mandatory($cfg, 'global', 'include', [], 1, 0);
	if (@$includes) {
		my $abs_cf = abs_path($config_file);
		my $main_cfg_dir = dirname($abs_cf);
		my %included = ( $abs_cf => 1 );
		do {
			$cfg->delval('global', 'include');
			foreach my $inc_file (@$includes) {
				$inc_file = "$main_cfg_dir/$inc_file" if $inc_file !~ m~^\s*/~;
				confdie("recursive include of config file $inc_file") if exists($included{$inc_file});
				my $new_cfg = load_ini_config($inc_file, -negativedeltas => 0, -import => $cfg) or
					confdie("Error(s) found importing settings from included config file $inc_file" .(@Config::IniFiles::errors ? ': '.join("\n", @Config::IniFiles::errors) : ''));
				$cfg = $new_cfg;
				$included{$inc_file} = 1;
			}
			$includes = get_mandatory($cfg, 'global', 'include', [], 1, 0);
		} while (@$includes);
	}

	# Process [ippool] section
	# Must be processed before [global] since it's existence may be verified there
	if ($cfg->SectionExists('ippool')) {
		my $ippool_conf = ETVPN::Conf->new_subconf();
		$ippool_conf->_assert_section($cfg, 'ippool', 0, 'ippool');
		$self->set('ippool', ETVPN::IPPool::new_from_conf($ippool_conf));
		$cfg->DeleteSection('ippool');
	}

	# Process [global] section
	$self->_assert_section($cfg, 'global', 0, 'global');
	$cfg->DeleteSection('global');

	# Process backend(s) section(s)
	my $backends = {};
	foreach my $section ($cfg->Sections()) {
		if ( my ($realm, $type) = $section =~ /^backend (\S+) (\S+)$/ ) {
			next unless __is_section_enabled($cfg, $section);
			confdie("realm name \"$realm\" must be unique") if exists($backends->{$realm});
			my $backend_conf = ETVPN::Conf->new_subconf(
				{
					# Each backend should 'inherit' global push routes
					'push routes' => $self->val('push routes'),
					'push routes group' => $self->val('push routes group'),
					# ... the ippool object if it exists
					'ippool' =>  $self->val('ippool'),
					# ... and any global ip pool group assignments
					'ipv4 pool group' => $self->val('ipv4 pool group'),
					# Also store the type for eventual display
					'backend type' => $type,
				}
			);
			my $backend_type_key = "backend $type";
			$backend_conf->_assert_section($cfg, $section, 1, 'backend', $backend_type_key);
			if (defined(my $backend_validator = $extra_validations{$backend_type_key})) {
				&$backend_validator($backend_conf);
			}
			my $backend = ETVPN::Backend::new_from_type($backend_conf, $type, $realm) or confdie("invalid backend type: $type");
			$backends->{$realm} = $backend;
			foreach my $realm_alias (@{$backend_conf->{'realm aliases'}}) {
				confdie("realm alias \"$realm_alias\" for backend $realm must be unique and not clash with any other realm name or alias") if exists($backends->{$realm_alias});
				$backends->{$realm_alias} = $backend;
			}
		}
		else {
			confdie("invalid section: [$section]");
		}
	}
	unless (%$backends) {
		confdie("need at least one enabled backend");
	}
	$self->set('backends', $backends);
}


sub get_mandatory {
	my ($cfg, $section, $name, $default, $as_array, $split_one_line) = @_;

	if ($as_array) {
		my @ret_array = $cfg->val($section, $name);
		if (@ret_array) {
			if (@ret_array == 1 && $split_one_line) {
				# also consider array when there are multiple values separated by spaces on a single line - TODO: somewhat of an hack...?
				@ret_array = split(/\s+/, $ret_array[0]);
			}
			return \@ret_array;
		}
	}
	else {
		my $ret = $cfg->val($section, $name);
		return $ret if defined($ret) && $ret ne '';
	}

	return $default if defined($default);
	confdie("missing mandatory configuration item in section [$section]: $name");
}


my %bool_val;
$bool_val{'yes'} = $bool_val{'true'} = $bool_val{1} = 1;
$bool_val{'no'} = $bool_val{'false'} = $bool_val{0} = 0;
sub get_mandatory_in_range {
	my ($cfg, $section, $name, $type, $default, $min, $max) = @_;
	my $val = get_mandatory($cfg, $section, $name, $default);

	if ($type eq 'uint') {
		confdie("configuration item \"$name\" must have unsigned integer value") unless $val =~ /^\d+$/;
	}
	elsif ($type eq 'int') {
		confdie("configuration item \"$name\" must have integer value") unless $val =~ /^[+-]?\d+$/;
	}
	elsif ($type eq 'bool') {
		confdie("configuration item \"$name\" must have boolean value (yes, no, true, false, 1 or 0)") unless exists($bool_val{$val});
		$val = $bool_val{$val};
	}

	if (defined($min) || defined($max)) {
		if ( (defined($min) && $val < $min) || (defined($max) && $val > $max) ) {
			my $motive;
			if (defined($min) && defined($max)) {
				$motive = "between $min and $max";
			}
			elsif (defined($min)) {
				$motive = "minimum $min";
			}
			else {
				# can only be if defined($max)
				$motive = "maximum $max";
			}
			confdie("configuration item \"$name\" must be $motive");
		}
	}

	return $val;
}


1;
