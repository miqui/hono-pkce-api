import { randomBytes, timingSafeEqual, createHash } from "node:crypto";

export const ALLOWED_SCOPES = ["notes:read", "notes:write"] as const;

export interface Client {
  id: string;
  redirectUris: string[];
}

export const clients = new Map<string, Client>([
  [
    "demo-client",
    { id: "demo-client", redirectUris: ["http://localhost:8080/callback"] },
  ],
]);

// Demo-only user. Not a real secret.
const DEMO_USER = { sub: "demo-user", username: "demo", password: "demo-password" };

function digest(s: string): Buffer {
  return createHash("sha256").update(s).digest();
}

export function authenticate(username: string, password: string): string | null {
  // Hash both sides so compare is fixed-length and constant-time.
  const userOk = timingSafeEqual(digest(username), digest(DEMO_USER.username));
  const passOk = timingSafeEqual(digest(password), digest(DEMO_USER.password));
  return userOk && passOk ? DEMO_USER.sub : null;
}

export interface AuthCode {
  clientId: string;
  redirectUri: string;
  challenge: string;
  scope: string;
  sub: string;
  expiresAt: number;
}

export const CODE_TTL_MS = 60_000;

export class CodeStore {
  private codes = new Map<string, AuthCode>();

  issue(data: Omit<AuthCode, "expiresAt">, now: number): string {
    const code = randomBytes(32).toString("base64url");
    this.codes.set(code, { ...data, expiresAt: now + CODE_TTL_MS });
    return code;
  }

  /** Atomically fetch and delete; a code can be consumed only once. */
  consume(code: string, now: number): AuthCode | null {
    const entry = this.codes.get(code);
    if (!entry) return null;
    this.codes.delete(code);
    if (entry.expiresAt <= now) return null;
    return entry;
  }
}
