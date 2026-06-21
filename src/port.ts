/**
 * The PORT of the 2fa domain — TOTP (RFC 6238).
 * period/digits are configurable. "alphanumeric" mode is an opt-in, PROPRIETARY
 * trade-off (out of RFC): standard authenticator apps can't read it — only one built for this mode.
 */
export type TotpMode = "rfc" | "alphanumeric";

export interface TotpOptions {
  /** Step in seconds (RFC default 30; values >30 supported). */
  period?: number;
  /** Code length (RFC default 6; values >6 supported). */
  digits?: number;
  /** "rfc" = numeric, interoperable. "alphanumeric" = proprietary opt-in. */
  mode?: TotpMode;
}

/** Parsed proprietary manual-registration string ("digits.period.secret"). */
export interface TreeSecret {
  secret: string;
  digits: number;
  period: number;
  mode: "alphanumeric";
}

export interface Totp {
  /** Generate a new base32 secret to store for the user. */
  generateSecret(): string;
  /** otpauth:// URI for the QR code (RFC mode — works in any standard authenticator app). */
  uri(secret: string, label: string, issuer: string): string;
  /**
   * PROPRIETARY manual-registration string "digits.period.secret" — one paste,
   * no advanced fields. Implies alphanumeric mode (readable only by an authenticator built for it).
   */
  treeSecret(secret: string): string;
  /** Current code for a secret at a given time. */
  generate(secret: string, atMs?: number): Promise<string>;
  /** Verify a code against the secret (current ±1 step, for clock skew). */
  verify(secret: string, code: string, atMs?: number): Promise<boolean>;
}
