import { Hono } from "hono";
import { createKeyStore } from "./keys.js";
import { CodeStore } from "./store.js";
import { authorizeGet, authorizePost } from "./authorize.js";
import { tokenHandler } from "./token.js";
import { metadata } from "./metadata.js";

export function createAuthRouter(deps: { now?: () => number } = {}): Hono {
  const now = deps.now ?? Date.now;
  const keys = createKeyStore();
  const codes = new CodeStore();
  const app = new Hono();

  app.get("/authorize", authorizeGet(codes));
  app.post("/authorize", authorizePost(codes, now));
  app.post("/token", tokenHandler(codes, keys, now));
  app.get("/.well-known/oauth-authorization-server", (c) => c.json(metadata()));
  app.get("/jwks.json", async (c) => c.json(await keys.getJwks()));
  return app;
}
