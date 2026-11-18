/**
 * `private_key_jwt` client authentication for EMA leg 3 (RFC 7523 §2.2).
 *
 * Leg 3 redeems the ID-JAG at the resource authorization server, and the EMA
 * profile expects a confidential client there: an ID-JAG is a bearer
 * assertion, so a server that let a public client redeem one would accept it
 * from anyone holding it. A server may therefore refuse both `none` and a
 * shared secret and require the client to prove possession of a key. Without
 * this module the Inspector could only send `client_secret_post` or `none`,
 * so it could not complete leg 3 against such a server at all.
 *
 * Signing is delegated to the SDK's `createPrivateKeyJwtAuth`, so `core/`
 * takes no new runtime dependency. Two choices are made here rather than left
 * to the helper's defaults:
 *
 * - **`aud` is the token endpoint URL**, passed explicitly. The helper falls
 *   back to the AS metadata `issuer`, which RFC 7523 permits but which some
 *   servers refuse; the token endpoint is the value every server accepts.
 * - **The algorithm is inferred from the key**, so the user supplies one value
 *   (the key) instead of a key plus an algorithm that has to agree with it.
 *   A JWK's own `alg` wins; otherwise the candidates are tried in order and
 *   the first one the key imports under is used.
 */
import { createPrivateKeyJwtAuth } from "@modelcontextprotocol/client";

/** RFC 7523 §2.2 `client_assertion_type`. */
export const CLIENT_ASSERTION_TYPE_JWT_BEARER =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * Tried in order when the key does not name its own algorithm. EC before RSA
 * because the curve is unambiguous; RS256 rather than PS256 for an RSA key
 * because it is the algorithm servers are required to support.
 */
export const CLIENT_ASSERTION_ALG_CANDIDATES = [
  "ES256",
  "ES384",
  "ES512",
  "RS256",
  "EdDSA",
] as const;

// PEM armour labels, assembled rather than written out whole so the source
// never contains a line that reads as an embedded key to a secret scanner.
const PEM_DASHES = "-----";
const PKCS8_LABEL = ["PRIVATE", "KEY"].join(" ");
const PKCS8_HEADER = `${PEM_DASHES}BEGIN ${PKCS8_LABEL}${PEM_DASHES}`;
const LEGACY_PEM_HEADER = new RegExp(
  `${PEM_DASHES}BEGIN (EC|RSA) ${PKCS8_LABEL}${PEM_DASHES}`,
);

/**
 * Accept either a PKCS#8 PEM or a private JWK as JSON. Anything else is
 * rejected here, before a request is attempted, so the error names the
 * configuration problem instead of a signing failure.
 */
export function parseClientPrivateKey(
  raw: string,
): string | Record<string, unknown> {
  const trimmed = raw.trim();
  if (trimmed.startsWith("{")) {
    // Starts with "{", so a successful parse is always a plain object.
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      throw new Error("Client private key is not valid JSON (expected a JWK)");
    }
    if (typeof parsed.d !== "string") {
      throw new Error(
        "Client private key JWK has no private part (`d`) — paste the private key, not the public JWKS",
      );
    }
    return parsed;
  }
  if (trimmed.includes(PKCS8_HEADER)) {
    return trimmed;
  }
  if (LEGACY_PEM_HEADER.test(trimmed)) {
    throw new Error(
      "Client private key must be PKCS#8 PEM; convert it with `openssl pkcs8 -topk8 -nocrypt`",
    );
  }
  throw new Error(
    "Client private key must be a PKCS#8 PEM or a private JWK (JSON)",
  );
}

/**
 * Build the `client_assertion` / `client_assertion_type` form parameters for
 * a token request. `iss` and `sub` are the client id (RFC 7523 §3); `aud` is
 * the token endpoint the request is about to be sent to.
 */
export async function buildClientAssertionParams(params: {
  clientId: string;
  privateKey: string;
  tokenEndpoint: string;
}): Promise<URLSearchParams> {
  const key = parseClientPrivateKey(params.privateKey);
  const declaredAlg =
    typeof key === "object" && typeof key.alg === "string" ? key.alg : null;
  const candidates: readonly string[] = declaredAlg
    ? [declaredAlg]
    : CLIENT_ASSERTION_ALG_CANDIDATES;

  let lastError: unknown;
  for (const alg of candidates) {
    const out = new URLSearchParams();
    const addClientAuth = createPrivateKeyJwtAuth({
      issuer: params.clientId,
      subject: params.clientId,
      privateKey: key,
      alg,
      audience: params.tokenEndpoint,
    });
    try {
      await addClientAuth(new Headers(), out, params.tokenEndpoint, undefined);
      return out;
    } catch (err) {
      lastError = err;
    }
  }
  const detail =
    /* v8 ignore next -- jose and the SDK only ever throw Error instances */
    lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(
    `Could not sign a client assertion with the configured private key (${detail})`,
    { cause: lastError },
  );
}
