Usually you need to:

```
perl Makefile.PL
make install
```

If you are packaging, you can pass the usual Makefile.PL options when running `perl Makefile.PL`. See your distribution packaging guidelines documentation. A .spec file is provided that should work for standard RPM based systems. Contributions for packaging for other distributions or other POSIX systems able to run a recent OpenVPN are welcome.

If you use systemd you'll also want to place `daemon/*.{service,target}` in their corresponding places (e.g. `/lib/systemd/system` if you are packaging, `/usr/local/lib/systemd/system` if you are making a manual install). You'll need to adjust the ownership and permissions of some of the files unless you want to run the daemon as root (which is not recommended). If you are creating a container, most likely you won't need to worry about any of this, but you may find useful taking some hints from the provided .spec and systemd files when building your container image.

If you don't use systemd, and are not creating a container, you'll have to provide your own init scripts. At the moment, there are none provided with this source, but contributions are welcome.

After installation you'll want to tweak the .ini file. By default it's installed as `etux-vpnserver.ini`, that's what is invoked by the "default" `etux-vpnserver-auth.service`, but you can have multiple instances running (for multiple OpenVPN instances) - you can use `etux-vpnserver-auth@.service` for that.

When editing the .ini file you'll come accross the need to generate a RSA private key. You can use the provided `tools/generic/create-master-key.pl` tool for that. Please be aware that this key must be kept as safe as possible and never leave your OpenVPN server(s), since it's what makes having your users' secrets stored on a shared backend like LDAP secure. If it's leaked, or if it's weak, then your system's MFA security is completely void. You've been warned.

As for configuring the webserver (used for Webauthn), you need to run the `webauthn.pl` PSGI and serve its requests via HTTPS. One easy and efficient way to do it is with uwsgi (which should come bundled with most recent distributions) and a webserver of your choice (tested under Apache and Nginx). You have example configurations in `webauthn/conf`. Contributions with configurations for other popular web servers are welcome.

The OpenVPN server configuration is out of scope on this document, however an example is provided in `openvpn-server-sample-conf` directory. What is important is to have the "management" and "management-client-auth" directives. What is also VERY important is to ensure the `.manage_passwd` (or whatever you name it) has SECURE permissions: it SHOULD NOT be world readable or writeable. If you ignore this and have your system cracked later, don't complain.

If want your clients to use WebAuthn, but they can't use an OpenVPN GUI that is compatible with the OPENURL feature (like Windows OpenVPN GUI, or the OpenVPN Connect clients), but on the other hand they are running an Operating System that bundles the `expect` command, you can give them one of the scripts inside the `compat-client-wrappers` directory. There is one provided for Linux Network Manager, and another for normal OpenVPN CLI. Please note that if you only plan to use TOTP (e.g. Google Authenticator) then you won't need this.
