import type { MiddlewareHandler } from "hono";
import type { AccessTokenClaims, ResourceEnv, Verifier } from "./types.js";

const REALM = 'Bearer realm="hono-pkce-api"';

export function parseScopes(scope: unknown): Set<string> {
  if (typeof scope !== "string") return new Set();
  return new Set(scope.split(" ").filter(Boolean));
}

function unauthorized(error?: string) {
  const header = error ? `${REALM}, error="${error}"` : REALM;
  return new Response(JSON.stringify({ error: error ?? "unauthorized" }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": header,
      "Cache-Control": "no-store",
    },
  });
}

export function bearerAuth(verify: Verifier): MiddlewareHandler<ResourceEnv> {
  return async (c, next) => {
    const header = c.req.header("Authorization");
    if (!header) return unauthorized();
    const m = /^bearer +(\S+)$/i.exec(header.trim());
    if (!m?.[1]) return unauthorized("invalid_request");
    let claims: AccessTokenClaims;
    try {
      claims = await verify(m[1]);
    } catch {
      return unauthorized("invalid_token");
    }
    c.set("auth", claims);
    await next();
  };
}

export function requireScope(scope: string): MiddlewareHandler<ResourceEnv> {
  return async (c, next) => {
    if (!parseScopes(c.get("auth").scope).has(scope)) {
      return new Response(
        JSON.stringify({ error: "insufficient_scope", scope }),
        {
          status: 403,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer error="insufficient_scope", scope="${scope}"`,
            "Cache-Control": "no-store",
          },
        },
      );
    }
    await next();
  };
}
