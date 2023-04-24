ETVPN Authenticator consists of a suite of tools and a daemon that provide username, password and MFA authentication to any OpenVPN Community edition server.

It was developed by Eurotux Informatica, S.A. and is released under the terms of the [GPLv2 license](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html#SEC1).

Currently supports the following authentication backends:
- LDAP, such as OpenLDAP, FreeIPA, Active Directory
- SQL, such as PostgreSQL, MySQL/MariaDB or SQLite (a set of command line tools is provided to manage SQL users, groups and their attributes)

MFA (Multi-Factor-Authentication) supported methods are:
- TOTP (e.g. Google Authenticator)
- WebauthN (the idea is to make the OpenVPN client open a web browser to authenticate a one time challenge from a hardware token, such as a Yubikey or similar)

The MFA secrets are RSA encrypted on the backends and additional command line tools are provided for the respective management tasks.

Basic setup instructions are provided in the [INSTALL.md](INSTALL.md) file, as well as a RPM spec file under `packaging/rpm` which has been tested and developed under Fedora Linux, but should work on other recent distributions provided they have the necessary (Perl and other) dependencies.
