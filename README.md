# Passkey Driver for Nails MFA Module

![license](https://img.shields.io/badge/license-MIT-green.svg)
[![tests](https://github.com/nails/driver-multi-factor-auth-passkey/actions/workflows/build_and_test.yml/badge.svg )](https://github.com/nails/driver-multi-factor-auth-passkey/action)

This is the "Passkey" driver for the Nails MFA module. It lets a user verify with a passkey — a fingerprint, face, screen-lock PIN, or security key — as their second factor, via the browser's WebAuthn ceremony.

All of the WebAuthn detail (the library, the credential store, the ceremony builders) lives in [`nails/module-auth`](https://github.com/nails/module-auth)'s `Passkey` service; this driver only adapts that service to the MFA module's `Driver` contract, using its `FormFragment` companion interface to render its own challenge/setup markup instead of a numeric code field.

Because a passkey enrolment is shared between passwordless sign-in and MFA, `reset()` is a no-op: removing this method never deletes the underlying passkeys, and a user who already has one is offered "use it as your second factor too" rather than being asked to create another.

Requires `nails/module-auth` with passkey support and `nails/module-multi-factor-auth` with `FormFragment` driver support.

Documentation: [https://docs.nailsapp.co.uk/modules/multi-factor-auth/drivers/passkey](https://docs.nailsapp.co.uk/modules/multi-factor-auth/drivers/passkey)
