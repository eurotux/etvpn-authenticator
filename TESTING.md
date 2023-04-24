Until you install the perl modules under `lib/` on the appropriate path of your system, you can perform test runs (or even run this inside a container) by making use of the PERLLIB environment variable, like so:

```
PERLLIB=`pwd`/lib ./daemon/etux-vpnserver-auth.pl -c ./etux-vpnserver.ini
PERLLIB=`pwd`/lib ./tools/otpauth/register-user-secret.pl -c ./etux-vpnserver.ini my_user
PERLLIB=`pwd`/lib ./tools/webauthn/register-user-secret.pl -c ./etux-vpnserver.ini list
```
