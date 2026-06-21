import type { Totp, TotpOptions, TotpMode, TreeSecret } from "./port";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // base36 for alphanumeric mode

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31] ?? "";
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31] ?? "";
  return out;
}

function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of clean) {
    const idx = BASE32.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function counterBytes(counter: number): Uint8Array {
  const buf = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  return buf;
}

async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
}

/** RFC 4226 dynamic truncation: take a 4-byte slice at the low-nibble offset, mask the sign bit -> 31-bit int. */
function truncate(hmac: Uint8Array): number {
  const offset = (hmac[hmac.length - 1] ?? 0) & 0x0f;
  return (
    (((hmac[offset] ?? 0) & 0x7f) << 24) |
    (((hmac[offset + 1] ?? 0) & 0xff) << 16) |
    (((hmac[offset + 2] ?? 0) & 0xff) << 8) |
    ((hmac[offset + 3] ?? 0) & 0xff)
  );
}

function toAlpha(n: number, len: number): string {
  let x = n;
  let out = "";
  for (let i = 0; i < len; i++) {
    out = (ALPHA[x % 36] ?? "0") + out;
    x = Math.floor(x / 36);
  }
  return out;
}

async function code(key: Uint8Array, counter: number, digits: number, mode: TotpMode): Promise<string> {
  const n = truncate(await hmacSha1(key, counterBytes(counter)));
  if (mode === "alphanumeric") return toAlpha(n, digits);
  return String(n % 10 ** digits).padStart(digits, "0");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Parse the proprietary "digits.period.secret" string (see Totp.treeSecret). */
export function parseTreeSecret(raw: string): TreeSecret | null {
  const m = /^(\d{1,2})\.(\d{1,4})\.([A-Z2-7\s]+=*)$/i.exec(raw.trim());
  if (!m) return null;
  const digits = Number.parseInt(m[1] ?? "", 10);
  const period = Number.parseInt(m[2] ?? "", 10);
  const secret = (m[3] ?? "").replace(/\s+/g, "").toUpperCase();
  if (!digits || !period || !/^[A-Z2-7]+=*$/.test(secret)) return null;
  return { secret, digits, period, mode: "alphanumeric" };
}

export function createTotp(options?: TotpOptions): Totp {
  const period = options?.period ?? 30;
  const digits = options?.digits ?? 6;
  const mode: TotpMode = options?.mode ?? "rfc";
  const counterAt = (atMs: number) => Math.floor(atMs / 1000 / period);

  return {
    generateSecret() {
      const b = new Uint8Array(20);
      crypto.getRandomValues(b);
      return base32Encode(b);
    },
    treeSecret(secret) {
      return `${digits}.${period}.${secret}`;
    },
    uri(secret, label, issuer) {
      const params = new URLSearchParams({
        secret,
        issuer,
        algorithm: "SHA1",
        digits: String(digits),
        period: String(period),
      });
      return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?${params.toString()}`;
    },
    async generate(secret, atMs = Date.now()) {
      return code(base32Decode(secret), counterAt(atMs), digits, mode);
    },
    async verify(secret, value, atMs = Date.now()) {
      const key = base32Decode(secret);
      const c = counterAt(atMs);
      for (const window of [0, -1, 1]) {
        if (timingSafeEqual(await code(key, c + window, digits, mode), value)) return true;
      }
      return false;
    },
  };
}
