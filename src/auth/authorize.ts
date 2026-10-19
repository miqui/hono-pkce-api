import type { Context } from "hono";
import { z } from "zod";
import { ALLOWED_SCOPES, authenticate, clients, type CodeStore } from "./store.js";
import { isValidChallenge } from "./pkce.js";

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

function htmlHeaders(c: Context) {
  c.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  c.header("X-Frame-Options", "DENY");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Cache-Control", "no-store");
}

function errorPage(c: Context, msg: string) {
  htmlHeaders(c);
  return c.html(`<!doctype html><title>Error</title><h1>Authorization error</h1><p>${esc(msg)}</p>`, 400);
}

const paramsSchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.string().min(1),
  scope: z.string().min(1),
  state: z.string().min(1).max(512),
  code_challenge: z.string().refine(isValidChallenge),
  code_challenge_method: z.literal("S256"),
});
type Params = z.infer<typeof paramsSchema>;

function redirectError(redirectUri: string, state: string | undefined, error: string, desc: string) {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", desc);
  if (state) u.searchParams.set("state", state);
  return u.toString();
}

/** Returns validated params, or a Response (error page / redirect). */
function validate(c: Context, raw: Record<string, unknown>): Params | Response {
  const str = (k: string) => (typeof raw[k] === "string" ? (raw[k] as string) : undefined);
  const client = clients.get(str("client_id") ?? "");
  if (!client) return errorPage(c, "Unknown client_id.");
  const ru = str("redirect_uri");
  if (!ru || !client.redirectUris.includes(ru)) return errorPage(c, "Invalid redirect_uri.");

  // redirect_uri is now trusted; remaining errors go back to the client.
  const state = str("state");
  if (!state) return c.redirect(redirectError(ru, undefined, "invalid_request", "state is required"), 302);
  const fail = (e: string, d: string) => c.redirect(redirectError(ru, state, e, d), 302);

  if (str("response_type") !== "code") return fail("unsupported_response_type", "response_type must be code");
  if (!str("code_challenge")) return fail("invalid_request", "code_challenge is required");
  if (str("code_challenge_method") !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
  const parsed = paramsSchema.safeParse(raw);
  if (!parsed.success) return fail("invalid_request", "malformed parameters");
  const scopes = parsed.data.scope.split(" ");
  if (!scopes.every((s) => (ALLOWED_SCOPES as readonly string[]).includes(s))) {
    return fail("invalid_scope", "unsupported scope");
  }
  return parsed.data;
}

function loginPage(c: Context, p: Params, error?: string) {
  htmlHeaders(c);
  const hidden = (Object.keys(p) as (keyof Params)[])
    .map((k) => `<input type="hidden" name="${k}" value="${esc(p[k])}">`)
    .join("");
  return c.html(`<!doctype html><meta charset="utf-8"><title>Sign in</title>
<h1>Sign in</h1><p>Client <b>${esc(p.client_id)}</b> requests: ${esc(p.scope)}</p>
${error ? `<p role="alert">${esc(error)}</p>` : ""}
<form method="post" action="/authorize">${hidden}
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form>`, error ? 401 : 200);
}

export function authorizeGet(codes: CodeStore) {
  void codes;
  return (c: Context) => {
    const v = validate(c, c.req.query());
    return v instanceof Response ? v : loginPage(c, v);
  };
}

export function authorizePost(codes: CodeStore, now: () => number) {
  return async (c: Context) => {
    const body = await c.req.parseBody();
    const v = validate(c, body);
    if (v instanceof Response) return v;
    const user = typeof body.username === "string" ? body.username : "";
    const pass = typeof body.password === "string" ? body.password : "";
    const sub = authenticate(user, pass);
    if (!sub) return loginPage(c, v, "Invalid username or password.");
    const code = codes.issue(
      { clientId: v.client_id, redirectUri: v.redirect_uri, challenge: v.code_challenge, scope: v.scope, sub },
      now(),
    );
    const u = new URL(v.redirect_uri);
    u.searchParams.set("code", code);
    u.searchParams.set("state", v.state);
    c.header("Cache-Control", "no-store");
    return c.redirect(u.toString(), 302);
  };
}
