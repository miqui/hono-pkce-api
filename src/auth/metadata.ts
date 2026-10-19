import { ISSUER } from "./keys.js";
import { ALLOWED_SCOPES } from "./store.js";

export function metadata() {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...ALLOWED_SCOPES],
    id_token_signing_alg_values_supported: [],
  };
}
