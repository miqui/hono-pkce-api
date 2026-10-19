import { createHash, timingSafeEqual } from "node:crypto";

const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

export const isValidChallenge = (s: string) => VERIFIER_RE.test(s);
export const isValidVerifier = (s: string) => VERIFIER_RE.test(s);

export function s256(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function verifyPkce(verifier: string, challenge: string): boolean {
  const a = Buffer.from(s256(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}
