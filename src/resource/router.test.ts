import { describe, expect, it } from "vitest";
import { createResourceRouter } from "./router.js";

const tokens: Record<string, { sub: string; scope: string; client_id: string }> = {
  alice: { sub: "alice", scope: "notes:read notes:write", client_id: "c" },
  bob: { sub: "bob", scope: "notes:read notes:write", client_id: "c" },
  ro: { sub: "alice", scope: "notes:read", client_id: "c" },
  none: { sub: "alice", scope: "openid", client_id: "c" },
};

const app = createResourceRouter({
  verifyAccessToken: async (t) => {
    const c = tokens[t];
    if (!c) throw new Error("bad token");
    return c;
  },
});

const call = (path: string, tok?: string, init: RequestInit = {}) =>
  app.request(path, {
    ...init,
    headers: {
      ...(tok ? { Authorization: `Bearer ${tok}` } : {}),
      ...(init.body ? { "Content-Type": "application/json" } : {}),
    },
  });
const json = (m: string, b: unknown) => ({ method: m, body: JSON.stringify(b) });
const note = { title: "t", body: "b" };

describe("bearer auth", () => {
  it("401 without header, bare challenge", async () => {
    const r = await call("/notes");
    expect(r.status).toBe(401);
    expect(r.headers.get("WWW-Authenticate")).toBe('Bearer realm="hono-pkce-api"');
    expect(r.headers.get("Cache-Control")).toBe("no-store");
  });
  it("401 on malformed header", async () => {
    const r = await app.request("/notes", { headers: { Authorization: "Basic abc" } });
    expect(r.status).toBe(401);
    expect(r.headers.get("WWW-Authenticate")).not.toContain("invalid_token");
  });
  it("401 invalid_token on bad token", async () => {
    const r = await call("/notes", "nope");
    expect(r.status).toBe(401);
    expect(r.headers.get("WWW-Authenticate")).toBe(
      'Bearer realm="hono-pkce-api", error="invalid_token"',
    );
  });
  it("scheme is case-insensitive", async () => {
    const r = await app.request("/notes", { headers: { Authorization: "bEaReR alice" } });
    expect(r.status).toBe(200);
  });
});

describe("scopes", () => {
  it("valid read", async () => {
    const r = await call("/notes", "ro");
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ notes: [] });
  });
  it("read-only cannot POST", async () => {
    const r = await call("/notes", "ro", json("POST", note));
    expect(r.status).toBe(403);
    expect(r.headers.get("WWW-Authenticate")).toBe(
      'Bearer error="insufficient_scope", scope="notes:write"',
    );
  });
  it("write-only scope missing read -> 403 on GET", async () => {
    const r = await call("/notes", "none");
    expect(r.status).toBe(403);
    expect(r.headers.get("WWW-Authenticate")).toContain('scope="notes:read"');
  });
});

describe("notes", () => {
  it("full CRUD lifecycle", async () => {
    const c = await call("/notes", "alice", json("POST", note));
    expect(c.status).toBe(201);
    const created = await c.json();
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.owner).toBeUndefined();
    expect((await (await call(`/notes/${created.id}`, "alice")).json()).title).toBe("t");
    const u = await call(`/notes/${created.id}`, "alice", json("PUT", { title: "n", body: "" }));
    expect(u.status).toBe(200);
    const updated = await u.json();
    expect(updated.title).toBe("n");
    expect(updated.createdAt).toBe(created.createdAt);
    expect((await (await call("/notes", "alice")).json()).notes).toHaveLength(1);
    const d = await call(`/notes/${created.id}`, "alice", { method: "DELETE" });
    expect(d.status).toBe(204);
    expect((await call(`/notes/${created.id}`, "alice")).status).toBe(404);
  });
  it("isolates users with 404", async () => {
    const created = await (await call("/notes", "alice", json("POST", note))).json();
    expect((await (await call("/notes", "bob")).json()).notes).toEqual([]);
    expect((await call(`/notes/${created.id}`, "bob")).status).toBe(404);
    expect((await call(`/notes/${created.id}`, "bob", json("PUT", note))).status).toBe(404);
    expect((await call(`/notes/${created.id}`, "bob", { method: "DELETE" })).status).toBe(404);
    expect((await call(`/notes/${created.id}`, "alice")).status).toBe(200);
  });
  it("validates input", async () => {
    for (const b of [{}, { title: "", body: "x" }, { title: "x".repeat(201), body: "" }, { title: "a", body: "x".repeat(10001) }, { title: 1, body: "" }]) {
      const r = await call("/notes", "alice", json("POST", b));
      expect(r.status).toBe(400);
      expect((await r.json()).error).toBe("validation_error");
    }
    const bad = await call("/notes", "alice", { method: "POST", body: "{nope" });
    expect(bad.status).toBe(400);
  });
  it("rejects oversized bodies", async () => {
    const r = await call("/notes", "alice", json("POST", { title: "a", body: "x".repeat(40000) }));
    expect(r.status).toBe(413);
  });
});
