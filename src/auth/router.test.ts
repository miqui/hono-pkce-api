import { describe, it, expect } from "vitest";
import { SignJWT, UnsecuredJWT, decodeProtectedHeader, generateKeyPair } from "jose";
import { createAuthRouter, createKeyStore } from "./router.js";
import { assertIssuer, ISSUER, AUDIENCE } from "./keys.js";
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

type Deps = NonNullable<Parameters<typeof createAuthRouter>[0]>;
type App = ReturnType<typeof createAuthRouter>;

function setup(now = () => 1_000_000, deps: Deps = {}) {
  return createAuthRouter({ now, ...deps });
}

interface Csrf {
  cookie: string;
  token: string;
}

const parseCsrf = (res: Response, html: string): Csrf => ({
  cookie: res.headers.get("set-cookie")!.split(";")[0]!,
  token: /name="csrf_token" value="([^"]+)"/.exec(html)![1]!,
});

/** GET the login form and pick up the CSRF cookie + hidden token, as a browser would. */
async function formToken(app: App, over: Record<string, string> = {}) {
  const res = await app.request("/authorize?" + form({ ...base, ...over }));
  expect(res.status).toBe(200);
  const sc = res.headers.get("set-cookie")!;
  return { ...parseCsrf(res, await res.text()), setCookie: sc };
}

interface LoginOpts {
  over?: Record<string, string>;
  username?: string;
  password?: string;
  csrf?: Csrf;
  headers?: Record<string, string>;
}

async function login(app: App, o: LoginOpts = {}) {
  const csrf = o.csrf ?? (await formToken(app));
  return app.request("/authorize", {
    method: "POST",
    headers: { ...FORM, cookie: csrf.cookie, ...o.headers },
    body: form({
      ...base,
      ...o.over,
      username: o.username ?? "demo",
      password: o.password ?? "demo-password",
      csrf_token: csrf.token,
    }),
  });
}

async function getCode(app: App) {
  const res = await login(app);
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location")!);
  expect(loc.searchParams.get("state")).toBe("xyz");
  return loc.searchParams.get("code")!;
}

const exchange = (app: App, o: Record<string, string>) =>
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
    const res = await login(setup(), { password: "wrong" });
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

    const { jwtVerify, createLocalJWKSet } = await import("jose");
    const jwks = await (await app.request("/jwks.json")).json();
    const { payload } = await jwtVerify(body.access_token, createLocalJWKSet(jwks), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["ES256"],
      typ: "at+jwt",
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

  it("rejects replayed code, still invalid_grant while the tombstone lives", async () => {
    let t = 1_000_000;
    const app = setup(() => t);
    const code = await getCode(app);
    expect((await exchange(app, { code })).status).toBe(200);
    t += 30_000; // inside the original 60s TTL
    const again = await exchange(app, { code });
    expect(again.status).toBe(400);
    expect((await again.json()).error).toBe("invalid_grant");
    expect(again.headers.get("cache-control")).toBe("no-store");
    t += 60_000; // past TTL: indistinguishable from unknown, still invalid_grant
    expect((await (await exchange(app, { code })).json()).error).toBe("invalid_grant");
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

  it("sets no-store/no-cache on every token error", async () => {
    const app = setup();
    const cases = [
      await exchange(app, { grant_type: "password", code: "x" }),
      await exchange(app, { code: "" }),
      await exchange(app, { code: "unknown" }),
      await exchange(app, { code: "x", code_verifier: "short" }),
      await app.request("/token", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }),
    ];
    for (const r of cases) {
      expect(r.status).toBe(400);
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("pragma")).toBe("no-cache");
    }
  });
});

describe("metadata & keys", () => {
  it("serves RFC 8414 metadata without id_token alg field", async () => {
    const m = await (await setup().request("/.well-known/oauth-authorization-server")).json();
    expect(m.code_challenge_methods_supported).toEqual(["S256"]);
    expect(m.issuer).toBe(ISSUER);
    expect(m).not.toHaveProperty("id_token_signing_alg_values_supported");
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

  it("an injected KeyStore is the one the router signs with", async () => {
    const keys = createKeyStore();
    const app = setup(() => Date.now(), { keys });
    const res = await exchange(app, { code: await getCode(app) });
    const { access_token } = await res.json();
    await expect(keys.verifyAccessToken(access_token)).resolves.toMatchObject({ sub: "demo-user" });
    expect((await (await app.request("/jwks.json")).json()).keys).toEqual((await keys.getJwks()).keys);
  });
});

describe("verifyAccessToken hardening (real signing key, one bad property each)", () => {
  async function fixture() {
    const pair = await generateKeyPair("ES256", { extractable: true });
    const ks = createKeyStore(pair);
    const mint = (
      header: Record<string, unknown> = {},
      o: { iss?: string; aud?: string } = {},
    ) =>
      new SignJWT({ scope: "s", client_id: "c" })
        .setProtectedHeader({ alg: "ES256", typ: "at+jwt", ...header })
        .setSubject("u")
        .setIssuer(o.iss ?? ISSUER)
        .setAudience(o.aud ?? AUDIENCE)
        .setExpirationTime("5m")
        .sign(pair.privateKey);
    return { ks, mint };
  }

  it("signs with typ at+jwt and accepts a well-formed token", async () => {
    const ks = createKeyStore();
    const tok = await ks.signAccessToken({ sub: "u", scope: "s", client_id: "c" });
    expect(decodeProtectedHeader(tok).typ).toBe("at+jwt");
    const { ks: ks2, mint } = await fixture();
    await expect(ks2.verifyAccessToken(await mint())).resolves.toEqual({ sub: "u", scope: "s", client_id: "c" });
  });

  it("rejects typ mismatch / missing typ", async () => {
    const { ks, mint } = await fixture();
    await expect(ks.verifyAccessToken(await mint({ typ: "JWT" }))).rejects.toThrow();
    await expect(ks.verifyAccessToken(await mint({ typ: undefined }))).rejects.toThrow();
  });

  it("rejects wrong iss and wrong aud", async () => {
    const { ks, mint } = await fixture();
    await expect(ks.verifyAccessToken(await mint({}, { iss: "http://evil.example" }))).rejects.toThrow();
    await expect(ks.verifyAccessToken(await mint({}, { aud: "other-api" }))).rejects.toThrow();
  });

  it("rejects alg=none and a wrong algorithm", async () => {
    const { ks } = await fixture();
    const none = new UnsecuredJWT({ scope: "s", client_id: "c" })
      .setSubject("u")
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setExpirationTime("5m")
      .encode();
    await expect(ks.verifyAccessToken(none)).rejects.toThrow();
    const { privateKey } = await generateKeyPair("RS256");
    const rs = await new SignJWT({ scope: "s", client_id: "c" })
      .setProtectedHeader({ alg: "RS256", typ: "at+jwt" })
      .setSubject("u")
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setExpirationTime("5m")
      .sign(privateKey);
    await expect(ks.verifyAccessToken(rs)).rejects.toThrow();
  });
});

describe("login CSRF", () => {
  it("sets an HttpOnly SameSite=Strict cookie scoped to /authorize and a hidden token", async () => {
    const { setCookie } = await formToken(setup());
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).toMatch(/Path=\/authorize/i);
    expect(setCookie).not.toMatch(/Secure/i); // test ISSUER is http
  });

  it("rejects a POST with no token or no cookie (403, no code)", async () => {
    const app = setup();
    const noToken = await app.request("/authorize", {
      method: "POST",
      headers: FORM,
      body: form({ ...base, username: "demo", password: "demo-password" }),
    });
    expect(noToken.status).toBe(403);
    expect(noToken.headers.get("location")).toBeNull();
    const csrf = await formToken(app);
    expect((await login(app, { csrf: { cookie: "", token: csrf.token } })).status).toBe(403);
    expect((await login(app, { csrf: { cookie: csrf.cookie, token: "" } })).status).toBe(403);
  });

  it("rejects a forged token, another form's token, and another instance's token", async () => {
    const app = setup();
    const a = await formToken(app);
    const b = await formToken(app);
    expect((await login(app, { csrf: { cookie: a.cookie, token: "forged" } })).status).toBe(403);
    expect((await login(app, { csrf: { cookie: a.cookie, token: b.token } })).status).toBe(403);
    expect((await login(setup(), { csrf: a })).status).toBe(403); // different HMAC key
  });

  it("rejects a tampered cookie value", async () => {
    const app = setup();
    const a = await formToken(app);
    const forged = { cookie: a.cookie.replace(/=.*?\./, "=AAAA."), token: a.token };
    expect((await login(app, { csrf: forged })).status).toBe(403);
  });

  it("is single use", async () => {
    const app = setup();
    const csrf = await formToken(app);
    expect((await login(app, { csrf })).status).toBe(302);
    expect((await login(app, { csrf })).status).toBe(403);
  });

  it("a failed login re-renders with a fresh token that works", async () => {
    const app = setup();
    const bad = await login(app, { password: "wrong" });
    expect(bad.status).toBe(401);
    const fresh = parseCsrf(bad, await bad.text());
    expect((await login(app, { csrf: fresh })).status).toBe(302);
  });

  it("expires after the TTL", async () => {
    let t = 1_000_000;
    const app = setup(() => t);
    const csrf = await formToken(app);
    t += 11 * 60_000;
    expect((await login(app, { csrf })).status).toBe(403);
  });

  it("rejects cross-origin POSTs even with a valid token", async () => {
    const app = setup();
    expect((await login(app, { headers: { origin: "http://evil.example" } })).status).toBe(403);
    expect((await login(app, { headers: { origin: "null" } })).status).toBe(403);
    expect((await login(app, { headers: { "sec-fetch-site": "cross-site" } })).status).toBe(403);
    expect((await login(app, { headers: { origin: new URL(ISSUER).origin } })).status).toBe(302);
  });

  it("re-validates all authorize params on POST", async () => {
    const app = setup();
    for (const [over, err] of [
      [{ scope: "admin" }, "invalid_scope"],
      [{ code_challenge_method: "plain" }, "invalid_request"],
      [{ code_challenge: "short" }, "invalid_request"],
      [{ response_type: "token" }, "unsupported_response_type"],
    ] as const) {
      const res = await login(app, { over });
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toContain(`error=${err}`);
    }
    const bad: Record<string, string>[] = [{ redirect_uri: "http://evil.example/cb" }, { client_id: "nope" }];
    for (const over of bad) {
      const res = await login(app, { over });
      expect(res.status).toBe(400);
      expect(res.headers.get("location")).toBeNull();
    }
  });
});

describe("login throttle", () => {
  const limits = { maxFailures: 3, windowMs: 60_000 };
  const ip = (addr: string) => () => addr;

  it("blocks after N failures with 429 + Retry-After, then recovers", async () => {
    let t = 1_000_000;
    const app = setup(() => t, { limits, clientIp: ip("1.1.1.1") });
    for (let i = 0; i < 3; i++) expect((await login(app, { password: "x" })).status).toBe(401);
    const blocked = await login(app); // even the correct password is refused
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBe("60");
    expect(blocked.headers.get("location")).toBeNull();
    t += 30_000;
    expect((await login(app)).headers.get("retry-after")).toBe("30");
    t += 31_000;
    expect((await login(app)).status).toBe(302);
  });

  it("a successful login resets the username counter", async () => {
    let n = 0; // distinct IPs so only the username counter is exercised
    const app = setup(() => 1_000_000, { limits, clientIp: () => `10.0.0.${n++}` });
    for (let i = 0; i < 2; i++) await login(app, { password: "x" });
    expect((await login(app)).status).toBe(302);
    for (let i = 0; i < 2; i++) expect((await login(app, { password: "x" })).status).toBe(401);
  });

  it("limits per IP across usernames, without affecting other IPs", async () => {
    const app = setup(() => 1_000_000, { limits, clientIp: ip("2.2.2.2") });
    for (const u of ["a", "b", "c"]) await login(app, { username: u, password: "x" });
    expect((await login(app, { username: "d", password: "x" })).status).toBe(429);
    const other = setup(() => 1_000_000, { limits, clientIp: ip("3.3.3.3") });
    expect((await login(other, { username: "d", password: "x" })).status).toBe(401);
  });

  it("limits per username across IPs", async () => {
    let n = 0;
    const app = setup(() => 1_000_000, { limits, clientIp: () => `10.1.0.${n++}` });
    for (let i = 0; i < 3; i++) await login(app, { password: "x" });
    expect((await login(app, { password: "x" })).status).toBe(429);
  });

  it("does not leak username existence: real and unknown users behave identically", async () => {
    const run = async (username: string) => {
      const app = setup(() => 1_000_000, { limits, clientIp: ip("4.4.4.4") });
      const out: [number, string | null, string][] = [];
      for (let i = 0; i < 4; i++) {
        const r = await login(app, { username, password: "x" });
        const html = (await r.text()).replace(/value="[^"]*"/g, "");
        out.push([r.status, r.headers.get("retry-after"), html]);
      }
      return out;
    };
    expect(await run("demo")).toEqual(await run("ghost"));
  });

  it("ignores X-Forwarded-For by default", async () => {
    const app = setup(() => 1_000_000, { limits });
    for (let i = 0; i < 3; i++) {
      await login(app, { username: `u${i}`, password: "x", headers: { "x-forwarded-for": `9.9.9.${i}` } });
    }
    const r = await login(app, { username: "u9", password: "x", headers: { "x-forwarded-for": "9.9.9.200" } });
    expect(r.status).toBe(429);
  });
});

describe("redirect_uri exact match", () => {
  it.each([
    ["trailing slash", RU + "/"],
    ["query appended", RU + "?a=b"],
    ["scheme/host case", "HTTP://LOCALHOST:8080/callback"],
    ["path case", "http://localhost:8080/Callback"],
    ["fragment", RU + "#x"],
    ["different port", "http://localhost:8081/callback"],
    ["userinfo trick", "http://localhost:8080@evil.example/callback"],
  ])("rejects %s (error page, no redirect)", async (_n, ru) => {
    const app = setup();
    const get = await app.request("/authorize?" + form({ ...base, redirect_uri: ru }));
    expect(get.status).toBe(400);
    expect(get.headers.get("location")).toBeNull();
    const post = await login(app, { over: { redirect_uri: ru } });
    expect(post.status).toBe(400);
    expect(post.headers.get("location")).toBeNull();
  });
});

describe("reflected output escaping", () => {
  const xss = `"><script>alert(1)</script>'&`;

  it("escapes state in the login page and CSP blocks script", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, state: xss }));
    const html = await res.text();
    expect(html).not.toContain("<script>");
    expect(html).toContain("&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;&#39;&#38;");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("invalid scope with markup redirects to the client, never reflects HTML", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, scope: `notes:read ${xss}` }));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).not.toContain("<script>");
  });

  it("error page does not reflect unknown client_id / redirect_uri input", async () => {
    const bad: Record<string, string>[] = [{ redirect_uri: xss }, { client_id: xss }];
    for (const over of bad) {
      const res = await setup().request("/authorize?" + form({ ...base, ...over }));
      expect(res.status).toBe(400);
      expect(await res.text()).not.toContain("<script>");
    }
  });

  it("error redirect carries state URL-encoded", async () => {
    const res = await setup().request("/authorize?" + form({ ...base, state: xss, scope: "admin" }));
    const loc = res.headers.get("location")!;
    expect(loc).not.toContain("<script>");
    expect(new URL(loc).searchParams.get("state")).toBe(xss);
  });
});

describe("startup checks", () => {
  it("throws in production with a non-https ISSUER only", () => {
    expect(() => assertIssuer("http://auth.example", "production")).toThrow(/https/);
    expect(() => assertIssuer("https://auth.example", "production")).not.toThrow();
    expect(() => assertIssuer("http://localhost:3000", "development")).not.toThrow();
  });
});
