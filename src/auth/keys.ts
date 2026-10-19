import { randomUUID } from "node:crypto";
import {
  SignJWT,
  jwtVerify,
  generateKeyPair,
  exportJWK,
  type JSONWebKeySet,
} from "jose";

/** Refuse to start in production with a non-https issuer. */
export function assertIssuer(issuer: string, env: string | undefined = process.env.NODE_ENV): void {
  if (env === "production" && new URL(issuer).protocol !== "https:") {
    throw new Error("ISSUER must be an https URL when NODE_ENV=production");
  }
}

export const ISSUER = process.env.ISSUER ?? "http://localhost:3000";
assertIssuer(ISSUER);
export const AUDIENCE = "hono-pkce-api";
const ALG = "ES256";

export interface AccessTokenClaims {
  sub: string;
  scope: string;
  client_id: string;
}

export interface KeyStore {
  signAccessToken(claims: AccessTokenClaims, ttlSec?: number): Promise<string>;
  verifyAccessToken(token: string): Promise<AccessTokenClaims>;
  getJwks(): Promise<JSONWebKeySet>;
}

/** `keyPair` is for tests; by default a fresh ES256 pair is generated. */
export function createKeyStore(keyPair?: { publicKey: CryptoKey; privateKey: CryptoKey }): KeyStore {
  const ready = (async () => {
    const { publicKey, privateKey } =
      keyPair ?? (await generateKeyPair(ALG, { extractable: true }));
    const kid = randomUUID();
    // exportJWK on the public key yields only public members.
    const pub = await exportJWK(publicKey);
    const jwk = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, kid, alg: ALG, use: "sig" };
    return { publicKey, privateKey, kid, jwk };
  })();

  return {
    async signAccessToken(claims, ttlSec = 300) {
      const { privateKey, kid } = await ready;
      return new SignJWT({ scope: claims.scope, client_id: claims.client_id })
        .setProtectedHeader({ alg: ALG, kid, typ: "at+jwt" })
        .setSubject(claims.sub)
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .setIssuedAt()
        .setExpirationTime(`${ttlSec}s`)
        .setJti(randomUUID())
        .sign(privateKey);
    },
    async verifyAccessToken(token) {
      const { publicKey } = await ready;
      const { payload } = await jwtVerify(token, publicKey, {
        issuer: ISSUER,
        audience: AUDIENCE,
        algorithms: [ALG],
        typ: "at+jwt",
      });
      if (
        typeof payload.sub !== "string" ||
        typeof payload.scope !== "string" ||
        typeof payload.client_id !== "string"
      ) {
        throw new Error("invalid token claims");
      }
      return { sub: payload.sub, scope: payload.scope, client_id: payload.client_id };
    },
    async getJwks() {
      const { jwk } = await ready;
      return { keys: [jwk] };
    },
  };
}
