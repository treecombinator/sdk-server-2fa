# @treecombinator/sdk-server-2fa

---

> Developed by Danthur Lice.\
> Copyright © 2026 Tree Combinator.\
> Contact: dev (at) treecombinator.com

---

The **2FA / TOTP** domain of the Tree Combinator SDK — a pure RFC 6238 implementation built on Web
Crypto, with no provider to configure. It provides the time-based one-time-password
primitives the Tree Combinator platform builds on, with zero runtime dependencies.

## Install

```bash
npm install github:treecombinator/sdk-server-2fa
```

## Use

```ts
import { createTotp } from "@treecombinator/sdk-server-2fa";

const totp = createTotp({ period: 30, digits: 6, mode: "rfc" });
const secret = totp.generateSecret();                  // store this per user
const uri = totp.uri(secret, "user@app.com", "MyApp"); // otpauth:// — render as a QR code
const ok = await totp.verify(secret, userEnteredCode);
```

`createTotp({ period?, digits?, mode? })` returns a TOTP instance:

- `generateSecret()` — a fresh base32 secret to store for the user.
- `uri(secret, label, issuer)` — the `otpauth://` URI to render as the QR code.
- `treeSecret(secret)` — proprietary one-paste manual-registration string (`"digits.period.secret"`).
- `generate(secret, atMs?)` — the current code at a given time (e.g. for testing).
- `verify(secret, code, atMs?)` — check a code (accepts the current step ±1, for clock skew).

Plus `parseTreeSecret(raw)` to parse the manual-registration string back.

## Notes

- `mode: "rfc"` (default) is numeric and interoperable with any standard authenticator app. `"alphanumeric"` is a proprietary opt-in — out of RFC, readable only by an authenticator built for it.
- `verify` allows ±1 step for clock skew. `parseTreeSecret` returns `null` on bad input — the package never throws.
