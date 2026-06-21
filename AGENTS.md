# AGENTS.md — @treecombinator/sdk-server-2fa

> Guide for AI agents. 2FA / TOTP (RFC 6238) domain of the Tree Combinator SDK. No provider — pure algorithm (Web Crypto).

## Use

```ts
import { createTotp } from "@treecombinator/sdk-server-2fa";
const totp = createTotp({ period: 30, digits: 6, mode: "rfc" });
const secret = totp.generateSecret();
const uri = totp.uri(secret, "user@app.com", "MyApp");   // otpauth:// for the QR
const ok = await totp.verify(secret, code);
```

`createTotp({ period?, digits?, mode? })` → `generateSecret()`, `uri(secret, label, issuer)`,
`treeSecret(secret)`, `generate(secret, atMs?)`, `verify(secret, code, atMs?)`. Plus `parseTreeSecret(raw)`.

## Notes
- `mode: "rfc"` (default) = numeric, interoperable. `"alphanumeric"` = proprietary opt-in (readable only by an authenticator built for it).
- `verify` allows ±1 step for clock skew. The package never throws — `parseTreeSecret` returns `null` on bad input. Zero dependencies.
