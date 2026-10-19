import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";

export const CSRF_COOKIE = "authz_csrf";
export const CSRF_FIELD = "csrf_token";
export const CSRF_TTL_MS = 10 * 60_000;

/**
 * Login-CSRF protection (signed double-submit + single use).
 *
 * Each render of the login form mints a random nonce. The nonce (with its expiry) goes in an
 * HttpOnly cookie; the form carries HMAC(key, nonce.expiry). The HMAC key is generated at
 * startup, so an attacker cannot forge a token for a cookie they cannot set, and a token
 * for one browser is useless in another. Every nonce is accepted at most once.
 *
 * SameSite=Strict works here: the cookie is set on the GET /authorize response and sent on
 * the same-site form POST. The final redirect back to the client needs no cookie.
 */
export class Csrf {
  private readonly key = randomBytes(32);
  private readonly used = new Map<string, number>();

  constructor(
    private readonly now: () => number,
    private readonly secure: boolean,
  ) {}

  private sign(value: string): string {
    return createHmac("sha256", this.key).update(value).digest("base64url");
  }

  /** Sets the cookie on the response and returns the token to embed in the form. */
  issue(c: Context): string {
    const value = `${randomBytes(24).toString("base64url")}.${this.now() + CSRF_TTL_MS}`;
    setCookie(c, CSRF_COOKIE, value, {
      httpOnly: true,
      sameSite: "Strict",
      secure: this.secure,
      path: "/authorize",
      maxAge: CSRF_TTL_MS / 1000,
    });
    return this.sign(value);
  }

  /** Verifies and burns the token. */
  verify(c: Context, token: unknown): boolean {
    const value = getCookie(c, CSRF_COOKIE);
    if (!value || typeof token !== "string") return false;
    const [nonce, expStr] = value.split(".");
    const exp = Number(expStr);
    const t = this.now();
    for (const [n, e] of this.used) if (e <= t) this.used.delete(n);
    if (!nonce || !Number.isFinite(exp) || exp <= t || this.used.has(nonce)) return false;
    const a = Buffer.from(this.sign(value));
    const b = Buffer.from(token);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
    this.used.set(nonce, exp);
    return true;
  }
}
