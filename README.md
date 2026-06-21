# @treecombinator/sdk-2fa

---

> Developed by Danthur Lice.\
> Copyright © 2026 Tree Combinator.\
> Contact: dev (at) treecombinator.com

---

The **2FA / TOTP** domain of the Tree Combinator SDK — a pure RFC 6238 implementation built on Web
Crypto, with no provider to configure. It provides the time-based one-time-password
primitives the Tree platform builds on, depending only on `@treecombinator/sdk-core` for
shared contracts and ports.

## Install

```bash
npm install github:treecombinator/sdk-2fa
```

API: createTotp({ period?, digits?, mode? }) -> generateSecret/uri/treeSecret/generate/verify; parseTreeSecret(raw)
