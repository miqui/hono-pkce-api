import type { Context } from "hono";
import type { CodeStore } from "./store.js";
import type { KeyStore } from "./keys.js";
import { isValidVerifier, verifyPkce } from "./pkce.js";

export const EXPIRES_IN = 300;

function err(c: Context, error: string, description: string, status: 400 | 401 = 400) {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
  return c.json({ error, error_description: description }, status);
}

export function tokenHandler(codes: CodeStore, keys: KeyStore, now: () => number) {
  return async (c: Context) => {
    const ct = c.req.header("content-type") ?? "";
    if (!ct.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      return err(c, "invalid_request", "content-type must be application/x-www-form-urlencoded");
    }
    const form = await c.req.parseBody();
    const get = (k: string) => (typeof form[k] === "string" ? (form[k] as string) : "");

    if (get("grant_type") !== "authorization_code") {
      return err(c, "unsupported_grant_type", "only authorization_code is supported");
    }
    const code = get("code");
    const verifier = get("code_verifier");
    const clientId = get("client_id");
    const redirectUri = get("redirect_uri");
    if (!code || !clientId || !redirectUri || !verifier) {
      return err(c, "invalid_request", "missing required parameter");
    }
    if (!isValidVerifier(verifier)) {
      return err(c, "invalid_request", "malformed code_verifier");
    }

    // Consume first: any attempt burns the code (replay-safe).
    const entry = codes.consume(code, now());
    if (!entry) return err(c, "invalid_grant", "invalid or expired code");
    if (entry.clientId !== clientId || entry.redirectUri !== redirectUri) {
      return err(c, "invalid_grant", "code does not match client or redirect_uri");
    }
    if (!verifyPkce(verifier, entry.challenge)) {
      return err(c, "invalid_grant", "PKCE verification failed");
    }
    const access_token = await keys.signAccessToken(
      { sub: entry.sub, scope: entry.scope, client_id: entry.clientId },
      EXPIRES_IN,
    );
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json({ access_token, token_type: "Bearer", expires_in: EXPIRES_IN, scope: entry.scope });
  };
}
