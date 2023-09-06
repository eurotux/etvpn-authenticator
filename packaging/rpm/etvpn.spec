%global etvpn_user       etvpn
%global etvpn_maingroup  %{etvpn_user}
%global etvpn_homedir    %{_sharedstatedir}/etvpn
%global etvpn_gecos      "ETVPN Authenticator service identity"
%global etvpnwww_user    etvpnwww
%global etvpnwww_group   %{etvpnwww_user}
%global etvpnwww_homedir %{etvpn_homedir}/www
%global etvpnwww_gecos   "ETVPN Authenticator web components identity"
%global etvpnsql_user    etvpnsql
%global etvpnsql_group   %{etvpnsql_user}
%global etvpnsql_homedir %{etvpn_homedir}
%global etvpnsql_gecos   "ETVPN Authenticator SQL user portal service identity"
%global etvpnsqlwww_user    etvpnsqlwww
%global etvpnsqlwww_group   %{etvpnsqlwww_user}
%global etvpnsqlwww_homedir %{etvpn_homedir}/www-sqluserportal
%global etvpnsqlwww_gecos   "ETVPN Authenticator SQL user portal web components identity"


Name:           etvpn
Version:        0.7.3
Release:        1%{?dist}
Summary:        ETVPN Authenticator suite for OpenVPN servers

License:        GPLv2
URL:            https://github.com/eurotux/etvpn-authenticator
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  systemd-rpm-macros
BuildRequires:  coreutils
BuildRequires:  make
BuildRequires:  perl-generators
BuildRequires:  perl-interpreter
BuildRequires:  perl(ExtUtils::MakeMaker) >= 6.76

Requires:       %{name}-web = %{version}-%{release}
Requires:       openvpn >= 2.5
Requires:       /usr/bin/oathtool
Requires(pre):  /usr/sbin/useradd /usr/bin/setfacl  perl-interpreter
Requires(post): perl-interpreter
Requires:       perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))
Requires:       perl(Authen::WebAuthn)
Requires:       perl(Bytes::Random::Secure)
Requires:       perl(CBOR::XS)
Requires:       perl(CGI::Session)
Requires:       perl(Config::IniFiles)
Requires:       perl(Convert::Base32)
Requires:       perl(Crypt::OpenSSL::RSA)
Requires:       perl(Cwd)
Requires:       perl(DBI)
Requires:       perl(Digest::SHA)
Requires:       perl(ExtUtils::MakeMaker)
Requires:       perl(Fcntl)
Requires:       perl(File::Basename)
Requires:       perl(File::stat)
Requires:       perl(File::Path)
Requires:       perl(File::Temp)
Requires:       perl(Getopt::Long)
Requires:       perl(IO::Interactive)
Requires:       perl(IO::Select)
Requires:       perl(IO::Socket)
Requires:       perl(JSON)
Requires:       perl(List::Util)
Requires:       perl(List::MoreUtils)
Requires:       perl(MIME::Base64)
Requires:       perl(Net::IP)
Requires:       perl(Net::LDAP)
Requires:       perl(POSIX)
Requires:       perl(Scalar::Util)
Requires:       perl(Storable)
Requires:       perl(Term::ReadKey)
Requires:       perl(URI)
Requires:       perl(URI::Escape)

%description
A suite of tools and a daemon that provide username, password and MFA authentication
to any OpenVPN Community edition server.


%package webauthn-compat-clients
Summary:        ETVPN Authenticator compatibility client wrappers
Requires:       expect

%description webauthn-compat-clients
Provides wrappers for using the regular OpenVPN community client or NetworkManager's nmcli
to connect to an OpenVPN instance with authentication controlled via ETVPN Authenticator
daemon and WebAuthn MFA challenge, for systems lacking a GUI that supports the OPENURL
client pending authentication method. In practice, if the ETVPN Authenticator daemon detects
that the client does not have such capability, it falls back to the regular CRV challenge
method prompting the user to open the URL manually. These scripts use expect to wrap around
that prompt and emulate the recent GUI's by opening the user's browser with the URL, and
retrying the connection with the respective CRV session token within a reasonable time.

Note that you do not need to install this package in your OpenVPN server (this is for client
machines), nor do you need to install it if your GUI already supports the aforementioned
method, nor is it needed if you aren't using WebAuthn challenges.


%package web
Summary:        ETVPN Authenticator web components
Requires:       %{name} = %{version}-%{release}
Requires:       perl(Plack::Request)
Requires:       perl(HTML::Template)

%description web
Provides ETVPN Authenticator web components such as the ones necessary for WebAuthn authentication.


%package uwsgi
Summary:        Configuration for ETVPN Authenticator web components and uWSGI
Requires:       %{name}-web = %{version}-%{release}
Requires:       uwsgi-plugin-psgi

%description uwsgi
Provides necessary configuration and dependencies for using ETVPN Authenticator web components with uWSGI.


%package httpd-uwsgi
Summary:        Configuration for ETVPN Authenticator web components using Apache web server and uWSGI
Requires:       %{name}-uwsgi = %{version}-%{release}
Requires:       httpd
Requires:       mod_ssl

%description httpd-uwsgi
Provides necessary configuration and dependencies for using ETVPN Authenticator web components with Apache web server and uWSGI.


%package nginx-uwsgi
Summary:        Configuration for ETVPN Authenticator web components using Nginx web server and uWSGI
Requires:       %{name}-uwsgi = %{version}-%{release}
Requires:       nginx

%description nginx-uwsgi
Provides necessary configuration and dependencies for using ETVPN Authenticator web components with Nginx web server and uWSGI.


%package sqluserportal
Summary:        ETVPN Authenticator User Self-Service Portal
Requires:       %{name} = %{version}-%{release}

%description sqluserportal
Provides a web portal that allows ETVPN Authenticator SQL based users to change their passwords.
The portal is composed by a daemon and a PSGI web interface.


%package sqluserportal-uwsgi
Summary:        Configuration for ETVPN Authenticator User Self-Service Portal and uWSGI
Requires:       %{name}-sqluserportal = %{version}-%{release}
Requires:       uwsgi-plugin-psgi

%description sqluserportal-uwsgi
Provides necessary configuration and dependencies for using ETVPN Authenticator User Self-Service Portal with uWSGI.


%package sqluserportal-httpd-uwsgi
Summary:        Configuration for ETVPN Authenticator User Self-Service Portal with Apache web server and uWSGI
Requires:       %{name}-sqluserportal-uwsgi = %{version}-%{release}
Requires:       httpd
Requires:       mod_ssl

%description sqluserportal-httpd-uwsgi
Provides necessary configuration and dependencies for using ETVPN Authenticator User Self-Service Portal with Apache web server and uWSGI.


%package sqluserportal-nginx-uwsgi
Summary:        Configuration for ETVPN Authenticator User Self-Service Portal service with Nginx web server and uWSGI
Requires:       %{name}-sqluserportal-uwsgi = %{version}-%{release}
Requires:       nginx

%description sqluserportal-nginx-uwsgi
Provides necessary configuration and dependencies for using ETVPN Authenticator User Self-Service Portal with Nginx web server and uWSGI.


%prep
%setup0 -c


%build
perl Makefile.PL INSTALLDIRS=vendor NO_PACKLIST=1 NO_PERLLOCAL=1

%install
rm -rf $RPM_BUILD_ROOT
# some permissions are reinforced in the main package %files section
# mainly because we will be using a dedicated user on the systemd file
%make_install \
     ETVPN_SYSTEM_CONFDIR=%{_sysconfdir} \
     ETVPN_SYSTEM_LIBEXECDIR=%{_libexecdir} \
     ETVPN_SYSTEM_SHAREDIR=%{_datadir}
mkdir -p %{buildroot}%{_unitdir}/etux-vpnserver-auth@etux-vpnserver.service.d
mkdir -p %{buildroot}%{_unitdir}/etux-vpnserver-sqluserportal@sqluserportal.service.d
install -t %{buildroot}%{_unitdir} -m 0644 \
        systemd/system/etux-vpnserver-*.service
install -t %{buildroot}%{_unitdir}/etux-vpnserver-auth@etux-vpnserver.service.d -m 0644 \
        systemd/system/etux-vpnserver-auth@etux-vpnserver.service.d/*.conf
install -t %{buildroot}%{_unitdir}/etux-vpnserver-sqluserportal@sqluserportal.service.d -m 0644 \
        systemd/system/etux-vpnserver-sqluserportal@sqluserportal.service.d/*.conf
# sqldb directory to facilitate storing sqlite database(s)
mkdir -p  %{buildroot}%{_sharedstatedir}/etvpn/sqldb
# ippool directory to facilitate storing a read-write sqlite database
mkdir -p  %{buildroot}%{_sharedstatedir}/etvpn/ippool
# compat client wrappers
mkdir -p %{buildroot}%{_bindir}
install -t %{buildroot}%{_bindir} compat-client-wrappers/etvpn-nm compat-client-wrappers/etvpn-ovpn
# session dir permissions are enforced in the respective webserver sub-package %files section
mkdir -p  %{buildroot}%{_sharedstatedir}/etvpn/cgi-sessions/{register,authorize}
mkdir -p  %{buildroot}%{_sharedstatedir}/etvpn/www-sqluserportal/cgi-sessions
mkdir -p  %{buildroot}%{_sharedstatedir}/etvpn/port-share
# uwsgi configuration
mkdir -p  %{buildroot}%{_sysconfdir}/uwsgi.d
install -t %{buildroot}%{_sysconfdir}/uwsgi.d -m 0640 webauthn/conf/uwsgi/etvpn.ini
install -t %{buildroot}%{_sysconfdir}/uwsgi.d -m 0640 sqluserportal/conf/uwsgi/etvpn-sqluserportal.ini
mkdir -p %{buildroot}%{_tmpfilesdir}
install -t %{buildroot}%{_tmpfilesdir} -m 0644 systemd/tmpfiles.d/etvpnwww.conf
install -t %{buildroot}%{_tmpfilesdir} -m 0644 systemd/tmpfiles.d/etvpnsqlwww.conf
# apache+uwsgi
mkdir -p  %{buildroot}%{_sysconfdir}/httpd/conf.d
install -t %{buildroot}%{_sysconfdir}/httpd/conf.d -m 0644 webauthn/conf/apache/etux-vpnserver*.conf
install -t %{buildroot}%{_sysconfdir}/httpd/conf.d -m 0644 sqluserportal/conf/apache/etux-vpnserver-sqluserportal*.conf
# nginx+uwsgi
mkdir -p  %{buildroot}%{_sysconfdir}/nginx/default.d
install -t %{buildroot}%{_sysconfdir}/nginx/default.d -m 0644 webauthn/conf/nginx/etux-vpnserver-uwsgi_locations.conf
install -t %{buildroot}%{_sysconfdir}/nginx/default.d -m 0644 sqluserportal/conf/nginx/etux-vpnserver-sqluserportal-uwsgi_locations.conf
mkdir -p  %{buildroot}%{_sysconfdir}/nginx/conf.d
install -t %{buildroot}%{_sysconfdir}/nginx/conf.d -m 0644 webauthn/conf/nginx/etux-vpnserver-uwsgi_upstream.conf
install -t %{buildroot}%{_sysconfdir}/nginx/conf.d -m 0644 sqluserportal/conf/nginx/etux-vpnserver-sqluserportal-uwsgi_upstream.conf

%clean
rm -rf $RPM_BUILD_ROOT


%pre
getent group %{etvpn_maingroup} >/dev/null || groupadd -r %{etvpn_maingroup}
getent group %{etvpnwww_group} >/dev/null || groupadd -r %{etvpnwww_group}
getent group %{etvpnsql_group} >/dev/null || groupadd -r %{etvpnsql_group}
getent passwd %{etvpn_user} >/dev/null || \
       useradd -r -g %{etvpn_maingroup} -G %{etvpnwww_group} -d %{etvpn_homedir} -s /sbin/nologin -c '%{etvpn_gecos}' %{etvpn_user}
getent passwd %{etvpnwww_user} >/dev/null || \
       useradd -r -g %{etvpnwww_group} -d %{etvpnwww_homedir} -s /sbin/nologin -c '%{etvpnwww_gecos}' %{etvpnwww_user}
getent passwd %{etvpnsql_user} >/dev/null || \
       useradd -r -g %{etvpnsql_group} -G %{etvpn_maingroup} -d %{etvpnsql_homedir} -s /sbin/nologin -c '%{etvpnsql_gecos}' %{etvpnsql_user}
exit 0

%pre sqluserportal
getent group %{etvpnsqlwww_group} >/dev/null || groupadd -r %{etvpnsqlwww_group}
getent passwd %{etvpnsqlwww_user} >/dev/null || \
       useradd -r -g %{etvpnsqlwww_group} -d %{etvpnsqlwww_homedir} -s /sbin/nologin -c '%{etvpnsqlwww_gecos}' %{etvpnsqlwww_user}
exit 0

%post httpd-uwsgi
id -Gn apache | grep -q '\b%{etvpnwww_group}\b' || usermod -G %{etvpnwww_group} -a apache
exit 0

%post nginx-uwsgi
id -Gn nginx | grep -q '\b%{etvpnwww_group}\b' || usermod -G %{etvpnwww_group} -a nginx
exit 0

%post sqluserportal-httpd-uwsgi
id -Gn apache | grep -q '\b%{etvpnsqlwww_group}\b' || usermod -G %{etvpnsqlwww_group} -a apache
exit 0

%post sqluserportal-nginx-uwsgi
id -Gn nginx | grep -q '\b%{etvpnsqlwww_group}\b' || usermod -G %{etvpnsqlwww_group} -a nginx
exit 0

%post
setfacl -m u:%{etvpnsql_user}:rwx,d:u:%{etvpnsql_user}:rw %{_sharedstatedir}/etvpn/sqldb
find %{_sharedstatedir}/etvpn/sqldb -type f -exec setfacl -m u:%{etvpnsql_user}:rw {} \;
setfacl -m d:u:%{etvpnwww_user}:r %{_sharedstatedir}/etvpn/port-share
for srv in `systemctl | perl -ne '/(etux-vpnserver-auth@.*\.service)/ and print "$1"'`;
do
    %systemd_post $srv
done

%post sqluserportal
setfacl -m d:u:%{etvpnsqlwww_user}:r %{_sharedstatedir}/etvpn/port-share
for srv in `systemctl | perl -ne '/(etux-vpnserver-sqluserportal@.*\.service)/ and print "$1"'`;
do
    %systemd_post $srv
done

%preun
for srv in `systemctl | perl -ne '/(etux-vpnserver-auth@.*\.service)/ and print "$1"'`;
do
    %systemd_preun $srv
done

%preun sqluserportal
for srv in `systemctl | perl -ne '/(etux-vpnserver-sqluserportal@.*\.service)/ and print "$1"'`;
do
    %systemd_preun $srv
done

%postun
for srv in `systemctl | perl -ne '/(etux-vpnserver-auth@.*\.service)/ and print "$1"'`;
do
    %systemd_postun_with_restart $srv
done

%postun sqluserportal
for srv in `systemctl | perl -ne '/(etux-vpnserver-sqluserportal@.*\.service)/ and print "$1"'`;
do
    %systemd_postun_with_restart $srv
done


%files
%license LICENSE
%doc INSTALL.md
%doc openvpn-server-sample-conf
%doc sql
%{perl_vendorlib}/*
%dir %attr(0750, root, %{etvpn_user}) %{_sysconfdir}/etvpn
%config(noreplace) %attr(0640, root, %{etvpn_maingroup}) %{_sysconfdir}/etvpn/etux-vpnserver.ini
%dir %{_libexecdir}/etvpn
%{_libexecdir}/etvpn/etux-vpnserver-auth
%{_libexecdir}/etvpn/tools/
%dir %{_datadir}/etvpn
%{_unitdir}/etux-vpnserver-auth*
%dir %attr(2710, root, %{etvpn_maingroup}) %{_sharedstatedir}/etvpn/sqldb
%dir %attr(2730, root, %{etvpn_maingroup}) %{_sharedstatedir}/etvpn/ippool

%files webauthn-compat-clients
%{_bindir}/etvpn-nm
%{_bindir}/etvpn-ovpn

%files web
%{_datadir}/etvpn/www/
%dir %attr(775, root, openvpn) %{_sharedstatedir}/etvpn/port-share

%files uwsgi
%config(noreplace) %attr(0440, %{etvpnwww_user}, %{etvpnwww_group}) %{_sysconfdir}/uwsgi.d/etvpn.ini
%{_tmpfilesdir}/etvpnwww.conf
%dir %attr(0710, root, %{etvpnwww_group}) %{_sharedstatedir}/etvpn/cgi-sessions
%dir %attr(2770, root, %{etvpnwww_group}) %{_sharedstatedir}/etvpn/cgi-sessions/register
%dir %attr(2770, root, %{etvpnwww_group}) %{_sharedstatedir}/etvpn/cgi-sessions/authorize

%files httpd-uwsgi
%config(noreplace) %{_sysconfdir}/httpd/conf.d/etux-vpnserver-uwsgi.conf

%files nginx-uwsgi
%config(noreplace) %{_sysconfdir}/nginx/conf.d/etux-vpnserver-uwsgi_upstream.conf
%config(noreplace) %{_sysconfdir}/nginx/default.d/etux-vpnserver-uwsgi_locations.conf

%files sqluserportal
%config(noreplace) %attr(0640, root, %{etvpnsql_group}) %{_sysconfdir}/etvpn/sqluserportal.ini
%{_libexecdir}/etvpn/etux-vpnserver-sqluserportal
%{_datadir}/etvpn/www-sqluserportal/
%{_unitdir}/etux-vpnserver-sqluserportal*

%files sqluserportal-uwsgi
%config(noreplace) %attr(0440, %{etvpnsqlwww_user}, %{etvpnsqlwww_group}) %{_sysconfdir}/uwsgi.d/etvpn-sqluserportal.ini
%{_tmpfilesdir}/etvpnsqlwww.conf
%dir %attr(2770, root, %{etvpnsqlwww_group}) %{_sharedstatedir}/etvpn/www-sqluserportal/cgi-sessions

%files sqluserportal-httpd-uwsgi
%config(noreplace) %{_sysconfdir}/httpd/conf.d/etux-vpnserver-sqluserportal-uwsgi.conf

%files sqluserportal-nginx-uwsgi
%config(noreplace) %{_sysconfdir}/nginx/conf.d/etux-vpnserver-sqluserportal-uwsgi_upstream.conf
%config(noreplace) %{_sysconfdir}/nginx/default.d/etux-vpnserver-sqluserportal-uwsgi_locations.conf


%changelog
* Wed Sep  6 2023 Rodrigo Araujo <roa@eurotux.com> - 0.7.3-1
- Update to version 0.7.3

* Thu Aug  3 2023 Rodrigo Araujo <roa@eurotux.com> - 0.7.2-1
- Update to version 0.7.2

* Thu Jul 13 2023 Rodrigo Araujo <roa@eurotux.com> - 0.7.1-1
- Update to version 0.7.1

* Tue Apr 25 2023 Rodrigo Araujo <roa@eurotux.com> - 0.7-1
- Initial RPM packaging
