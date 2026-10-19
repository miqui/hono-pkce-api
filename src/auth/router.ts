import { Hono, type Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import { assertIssuer, createKeyStore, ISSUER, type KeyStore } from "./keys.js";
import { CodeStore } from "./store.js";
import { authorizeGet, authorizePost } from "./authorize.js";
import { tokenHandler } from "./token.js";
import { metadata } from "./metadata.js";
import { Csrf } from "./csrf.js";
import { DEFAULT_LIMITS, FailureLimiter, type ThrottleLimits } from "./throttle.js";

export { createKeyStore, type KeyStore };

export interface AuthDeps {
  now?: () => number;
  /** Share one instance with the resource router so it verifies our tokens. */
  keys?: KeyStore;
  /** Per-username and per-IP failure limits for login. */
  limits?: ThrottleLimits;
  /** Override client-IP detection. Default: socket address; X-Forwarded-For is NOT trusted. */
  clientIp?: (c: Context) => string;
}

function socketIp(c: Context): string {
  try {
    return getConnInfo(c).remote.address ?? "unknown";
  } catch {
    return "unknown"; // no socket (e.g. app.request in tests)
  }
}

export function createAuthRouter(deps: AuthDeps = {}): Hono {
  assertIssuer(ISSUER);
  const now = deps.now ?? Date.now;
  const keys = deps.keys ?? createKeyStore();
  const codes = new CodeStore();
  const csrf = new Csrf(now, new URL(ISSUER).protocol === "https:");
  const limits = deps.limits ?? DEFAULT_LIMITS;
  const throttle = {
    byUser: new FailureLimiter(limits, now),
    byIp: new FailureLimiter(limits, now),
    clientIp: deps.clientIp ?? socketIp,
  };
  const app = new Hono();

  app.get("/authorize", authorizeGet(csrf));
  app.post("/authorize", authorizePost(codes, now, csrf, throttle));
  app.post("/token", tokenHandler(codes, keys, now));
  app.get("/.well-known/oauth-authorization-server", (c) => c.json(metadata()));
  app.get("/jwks.json", async (c) => c.json(await keys.getJwks()));
  return app;
}
