# WebAuthn for EGroupware

Adds [WebAuthn](https://www.w3.org/TR/webauthn/) (FIDO2/U2F) support to [EGroupware](https://github.com/EGroupware/egroupware) as a second authentication factor: security keys, passkeys, and platform authenticators (Touch ID, Windows Hello, Android biometrics) instead of, or in addition to, one-time codes.

Built on [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework), the reference PHP implementation of the standard.

## What is WebAuthn?

WebAuthn is a W3C/FIDO Alliance standard for authenticating with public-key cryptography instead of a shared secret. When you register an authenticator, it generates a key pair and gives the server only the public key; the private key never leaves the device (or its secure enclave/TPM). Logging in means signing a server-issued, single-use challenge with that private key - there is no shared secret to phish, replay, or leak from a server-side breach, and each credential is bound to the exact origin it was registered for, which also rules out look-alike phishing domains.

## What this app does

- Adds a "WebAuthn / U2F tokens" section under **Preferences > Password & Security**, where users register one or more authenticators.
- Once at least one token/passkey is registered, EGroupware requires a successful WebAuthn ceremony as a second factor after the regular password login (see the `multifactor_policy` hook).
- Stores only the public key and metadata needed to verify future logins (`egw_webauthn_pubkeys`); the actual credential/private key stays on the user's authenticator.

## Requirements

- A browser with WebAuthn support (recent Chrome, Firefox, Edge, Safari).
- An authenticator: a FIDO2/U2F security key, or a platform authenticator (Touch ID, Windows Hello, Android/Chrome biometrics).
- HTTPS - WebAuthn requires a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (an exception is made for `localhost` during development).

## License

GPL-2.0-or-later, see [LICENSE.md](LICENSE.md).
