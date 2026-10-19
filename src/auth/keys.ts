import { randomUUID } from "node:crypto";
import {
  SignJWT,
  jwtVerify,
  generateKeyPair,
  exportJWK,
  type JSONWebKeySet,
  type CryptoKey,
} from "jose";

export const ISSUER = process.env.ISSUER ?? "http://localhost:3000";
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

export function createKeyStore(): KeyStore {
  const ready = (async () => {
    const { publicKey, privateKey } = await generateKeyPair(ALG, {
      extractable: true,
    });
    const kid = randomUUID();
    // exportJWK on the public key yields only public members.
    const pub = await exportJWK(publicKey);
    const jwk = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, kid, alg: ALG, use: "sig" };
    return { publicKey: publicKey as CryptoKey, privateKey: privateKey as CryptoKey, kid, jwk };
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
