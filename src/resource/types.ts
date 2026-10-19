export interface AccessTokenClaims {
  sub: string;
  scope: string;
  client_id: string;
}

export type Verifier = (token: string) => Promise<AccessTokenClaims>;

export type ResourceEnv = { Variables: { auth: AccessTokenClaims } };
