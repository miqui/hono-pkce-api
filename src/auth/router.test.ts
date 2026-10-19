import { describe, it, expect } from "vitest";
import { createAuthRouter } from "./router.js";
import { createKeyStore, ISSUER, AUDIENCE } from "./keys.js";
import { s256 } from "./pkce.js";

// RFC 7636 Appendix B
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const RU = "http://localhost:8080/callback";

const base = {
  response_type: "code",
  client_id: "demo-client",
  redirect_uri: RU,
  scope: "notes:read",
  state: "xyz",
  code_challenge: CHALLENGE,
  code_challenge_method: "S256",
};

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const FORM = { "content-type": "application/x-www-form-urlencoded" };

function setup(now = () => 1_000_000) {
  return createAuthRouter({ now });
}

async function login(app: ReturnType<typeof setup>, over: Record<string, string> = {}) {
  return app.request("/authorize", {
    method: "POST",
    headers: FORM,
    body: form({ ...base, ...over, username: "demo", password: "demo-password" }),
  });
}

async function getCode(app: ReturnType<typeof setup>) {
  const res = await login(app);
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location")!);
  expect(loc.searchParams.get("state")).toBe("xyz");
  return loc.searchParams.get("code")!;
}

const exchange = (app: ReturnType<typeof setup>, o: Record<string, string>) =>
  app.request("/token", {
    method: "POST",
    headers: FORM,
    body: form({
      grant_type: "authorization_code",
      client_id: "demo-client",
      redirect_uri: RU,
      code_verifier: VERIFIER,
      ...o,
    }),
  });

describe("authorize", () => {
  it("shows login form with security headers", async () => {
    const res = await setup().request("/authorize?" + form(base));
    expect(res.status).toBe(200);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(await res.text()).toContain("<form");
  });

  it("rejects missing challenge", async () => {
    const { code_challenge: _c, ...rest } = base;
    void _c;
    const res = await setup().request("/authorize?" + form(rest));
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).searchParams.get("error")).toBe("invalid_request");
  });

  it("rejects plain method", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, code_challenge_method: "plain" }));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("error=invalid_request");
  });

  it("rejects missing state", async () => {
    const { state: _s, ...rest } = base;
    void _s;
    const res = await setup().request("/authorize?" + form(rest));
    expect(res.headers.get("location")).toContain("error=invalid_request");
  });

  it("rejects bad scope", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, scope: "notes:read admin" }));
    expect(res.headers.get("location")).toContain("error=invalid_scope");
  });

  it("shows error page (no redirect) for wrong redirect_uri", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, redirect_uri: "http://evil.example/cb" }));
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("shows error page for unknown client", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, client_id: "nope" }));
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("re-renders login on bad password without issuing a code", async () => {
    const res = await setup().request("/authorize", {
      method: "POST",
      headers: FORM,
      body: form({ ...base, username: "demo", password: "wrong" }),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("token", () => {
  it("happy path with RFC 7636 vector; claims verify via JWKS", async () => {
    expect(s256(VERIFIER)).toBe(CHALLENGE);
    const app = setup();
    const res = await exchange(app, { code: await getCode(app) });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");
    const body = await res.json();
    expect(body).toMatchObject({ token_type: "Bearer", expires_in: 300, scope: "notes:read" });
    expect(body.refresh_token).toBeUndefined();

    const { jwtVerify, createLocalJWKSet, decodeProtectedHeader } = await import("jose");
    const jwks = await (await app.request("/jwks.json")).json();
    const { payload } = await jwtVerify(body.access_token, createLocalJWKSet(jwks), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["ES256"],
    });
    expect(payload).toMatchObject({ sub: "demo-user", scope: "notes:read", client_id: "demo-client" });
    expect(payload.jti).toBeTruthy();
    expect(payload.exp! - payload.iat!).toBe(300);
    expect(decodeProtectedHeader(body.access_token).kid).toBe(jwks.keys[0].kid);
  });

  it("rejects wrong verifier", async () => {
    const app = setup();
    const res = await exchange(app, { code: await getCode(app), code_verifier: "a".repeat(43) });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_grant");
  });

  it("rejects malformed verifier", async () => {
    const app = setup();
    const res = await exchange(app, { code: await getCode(app), code_verifier: "short" });
    expect((await res.json()).error).toBe("invalid_request");
  });

  it("rejects replayed code", async () => {
    const app = setup();
    const code = await getCode(app);
    expect((await exchange(app, { code })).status).toBe(200);
    const again = await exchange(app, { code });
    expect(again.status).toBe(400);
    expect((await again.json()).error).toBe("invalid_grant");
  });

  it("a failed attempt burns the code", async () => {
    const app = setup();
    const code = await getCode(app);
    await exchange(app, { code, code_verifier: "a".repeat(43) });
    expect((await exchange(app, { code })).status).toBe(400);
  });

  it("rejects expired code", async () => {
    let t = 1_000_000;
    const app = setup(() => t);
    const code = await getCode(app);
    t += 61_000;
    const res = await exchange(app, { code });
    expect((await res.json()).error).toBe("invalid_grant");
  });

  it("rejects mismatched redirect_uri and client_id", async () => {
    const app = setup();
    const r1 = await exchange(app, { code: await getCode(app), redirect_uri: "http://localhost:8080/other" });
    expect((await r1.json()).error).toBe("invalid_grant");
    const r2 = await exchange(app, { code: await getCode(app), client_id: "other" });
    expect((await r2.json()).error).toBe("invalid_grant");
  });

  it("rejects unsupported grant and wrong content-type", async () => {
    const app = setup();
    const r1 = await exchange(app, { grant_type: "password", code: "x" });
    expect((await r1.json()).error).toBe("unsupported_grant_type");
    const r2 = await app.request("/token", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(r2.status).toBe(400);
  });
});

describe("metadata & keys", () => {
  it("serves RFC 8414 metadata", async () => {
    const m = await (await setup().request("/.well-known/oauth-authorization-server")).json();
    expect(m.code_challenge_methods_supported).toEqual(["S256"]);
    expect(m.issuer).toBe(ISSUER);
  });

  it("JWKS has no private material", async () => {
    const jwks = await (await setup().request("/jwks.json")).json();
    expect(jwks.keys).toHaveLength(1);
    for (const k of jwks.keys) {
      expect(k.d).toBeUndefined();
      expect(k.kid).toBeTruthy();
    }
  });

  it("verifyAccessToken rejects tokens from another key store", async () => {
    const a = createKeyStore();
    const b = createKeyStore();
    const tok = await a.signAccessToken({ sub: "u", scope: "notes:read", client_id: "c" });
    await expect(a.verifyAccessToken(tok)).resolves.toEqual({ sub: "u", scope: "notes:read", client_id: "c" });
    await expect(b.verifyAccessToken(tok)).rejects.toThrow();
    const expired = await a.signAccessToken({ sub: "u", scope: "s", client_id: "c" }, -10);
    await expect(a.verifyAccessToken(expired)).rejects.toThrow();
  });
});
