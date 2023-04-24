# Possible requests and replies

Each request should be well formed JSON in a **single line**, terminated with CRLF (\r\n) via a TCP socket connection made to a configurable address/port.

The GUI should **always**:
- log in some manner **every** operation, including timestamp, originating IP address, username involved and operation type requested, but without logging any tokens, passwords or challenges, while still providing some means to correlate each log entry (e.g. referring every time a web session ID that is **not** the token returned by the daemon)
- explicitly log **every** error encountered, including (but not limited to) when invalid or inconsistent replies are sent by the daemon
- validate each daemon reply and consider the reply as invalid if either the type on the reply is different from the request, as well as it should check for the existence of each of the mandatory attributes according to the different reply types and combinations as described below (i.e. it **must** check if the attribute is defined, not empty and of the correct type when another attribute mandates it, for example if "challenge_type" is "webauthn", a "challenge" is supposed to be also defined, and it must be a non-empty array)

In case of a malformed reply by the daemon, the GUI should indicate that an internal error occurred, and ask the user to retry the operation later. The error should also be logged in the respective application log, as stated above.


## Malformed requests

If the daemon considers a request is malformed (e.g. invalid JSON, invalid type attribute, missing mandatory parameters) the reply is always:
```
{ "result":"badrequest" }  // GUI should log this, forget any existing token by invalidating any for of login session, inform the user that an internal error occurred and ask them to inform the system administrator, and finally go back to initial login page
```


## Login

Request:
```
{ "type":"login", "username":"<username>", "password":"<password>" }
```

Reply is one of:
```
{ "type":"login", "result":"fail" }  // GUI should indicate login failure
{ "type":"login", "result":"error" }  // GUI should indicate that an internal error occurred, and ask the user to retry the operation later
{ "type":"login", "result":"ok", "token":"<token>", "challenge_type":"webauthn", "challenge":[<byte array, eg: 51,198,...,62,224], "rpID":"<rpid>", "credential_id":[<byte array, eg: 50,135,...,128,121] }   // Mandatory WebAuthn challenge needed, GUI should present the user the WebAuthn challenge corresponding to the given parameters
{ "type":"login", "result":"ok", "token":"<token>", "challenge_type":"totp" }   // Mandatory TOTP challenge needed, GUI should prompt the user for their authenticator code
{ "type":"login", "result":"ok", "token":"<token>" }  // Login successful (no mandatory challenge needed), GUI can proceed and skip Challenge Authorization
```

Notes:
- obtained token will be needed for every subsequent request
- it's guaranteed that each token will expire after some time or when the daemon is restarted (see possible replies below to determine when that happens)


## Challenge Authorization

Request:
```
{ "type":"challenge_authorization", "token":"<token>", "authenticator_data": "<base64url encoded value>", "data": "<base64url encoded value>", "signature": "<base64url encoded value>" }  // If challenge_type was "webauthn" when token was obtained
{ "type":"challenge_authorization", "token":"<token>", "code":"<autentication code given by user>" }  // If challenge_type was "totp" when token was obtained
```

Reply is one of:
```
{ "type":"challenge_authorization", "result":"fail" }  // GUI should indicate challenge validation failure, can allow for up to 3 retries if challenge_type was "totp", and fail immediatly otherwise
{ "type":"challenge_authorization", "result":"invalid" }  // GUI should go back to initial login page and indicate invalid or expired token
{ "type":"challenge_authorization", "result":"error" }  // GUI should indicate that an internal error occurred, and ask the user to retry the operation later
{ "type":"challenge_authorization", "result":"ok" }  // Challenge validation successful, GUI can proceed
```


## Token validity check

Request:
```
{ "type":"check", "username":"<username>", "token":"<token>" }
```

Reply is one of:
```
{ "type":"check", "result":"invalid" }  // GUI should should go back to initial login page and indicate invalid or expired token
{ "type":"check", "result":"error" }  // GUI should indicate that an internal error occurred, and ask the user to retry the operation later
{ "type":"check", "result":"ok" }  // Token is valid, GUI can proceed
```


## Password changing request

Request:
```
{ "type":"passwd", "token":"<token>", "old_password":"<old_password>", "new_password":"<new_password>" }  // It's mostly advisable that the GUI prompts twice for the new_password and ensures both values match before making this request (to ensure the user entered the password they intended), since and all 3 prompts/fields should mask or not echo the password (e.g. in HTML input type="password" should be used)
```

Reply is one of:
```
{ "type":"passwd", "result":"fail" }  // GUI should should indicate that the old password is incorrect and allow user to retry
{ "type":"passwd", "result":"same" }  // GUI should should indicate that the new password cannot be the same as the old password and allow user to retry
{ "type":"passwd", "result":"weak" }  // GUI should should indicate that the new password is too weak and allow user to retry
{ "type":"passwd", "result":"invalid" }  // GUI should should go back to initial login page and indicate invalid or expired token
{ "type":"passwd", "result":"error" }  // GUI should indicate that an internal error occurred, and ask the user to retry the operation later
{ "type":"passwd", "result":"ok" }  // GUI should indicate that the password was successfully changed
```

Notes:
- before making a password changing request, the token must have previously been used successfully in the respetive challenge authorization request (unless it corresponds to a user with no mandatory challenge needed) or it will be automatically invalidated on the daemon side (in which case `"result":"badrequest"` is returned on the reply).


## Logout

Request:
```
{ "type":"logout", "token":"<token>" }
```

Reply is always:
```
{ "type":"logout", "result":"ok" }  // GUI should go back to initial login page
```
