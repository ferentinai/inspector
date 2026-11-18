import { describe, it, expect } from "vitest";
import {
  decodeProtectedHeader,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  jwtVerify,
} from "jose";
import {
  buildClientAssertionParams,
  CLIENT_ASSERTION_TYPE_JWT_BEARER,
  parseClientPrivateKey,
} from "@inspector/core/auth/ema/clientAssertion.js";

const CLIENT_ID = "resource-client";
const TOKEN_ENDPOINT = "https://as.test/token";

// Keys are generated per run so no key material is committed.
async function keyPair(alg: string) {
  return generateKeyPair(alg, { extractable: true });
}

async function verifyAssertion(
  params: URLSearchParams,
  publicKey: CryptoKey,
): Promise<{ alg: string; payload: Record<string, unknown> }> {
  expect(params.get("client_assertion_type")).toBe(
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
  );
  const assertion = params.get("client_assertion");
  expect(assertion).toBeTruthy();
  const { payload } = await jwtVerify(assertion!, publicKey, {
    issuer: CLIENT_ID,
    subject: CLIENT_ID,
    audience: TOKEN_ENDPOINT,
  });
  return {
    alg: decodeProtectedHeader(assertion!).alg as string,
    payload: payload as Record<string, unknown>,
  };
}

describe("buildClientAssertionParams", () => {
  it("signs with an EC PKCS#8 PEM, inferring ES256, aud = token endpoint", async () => {
    const { privateKey, publicKey } = await keyPair("ES256");
    const params = await buildClientAssertionParams({
      clientId: CLIENT_ID,
      privateKey: await exportPKCS8(privateKey),
      tokenEndpoint: TOKEN_ENDPOINT,
    });
    const { alg, payload } = await verifyAssertion(params, publicKey);
    expect(alg).toBe("ES256");
    expect(typeof payload.jti).toBe("string");
  });

  it("infers RS256 for an RSA PKCS#8 PEM", async () => {
    const { privateKey, publicKey } = await keyPair("RS256");
    const params = await buildClientAssertionParams({
      clientId: CLIENT_ID,
      privateKey: await exportPKCS8(privateKey),
      tokenEndpoint: TOKEN_ENDPOINT,
    });
    expect((await verifyAssertion(params, publicKey)).alg).toBe("RS256");
  });

  it("accepts a PEM whose line breaks were lost on paste", async () => {
    const { privateKey, publicKey } = await keyPair("ES256");
    const flattened = (await exportPKCS8(privateKey)).replace(/\n/g, "");
    const params = await buildClientAssertionParams({
      clientId: CLIENT_ID,
      privateKey: flattened,
      tokenEndpoint: TOKEN_ENDPOINT,
    });
    expect((await verifyAssertion(params, publicKey)).alg).toBe("ES256");
  });

  it("uses a JWK's own alg when present", async () => {
    const { privateKey, publicKey } = await keyPair("ES384");
    const jwk = { ...(await exportJWK(privateKey)), alg: "ES384" };
    const params = await buildClientAssertionParams({
      clientId: CLIENT_ID,
      privateKey: JSON.stringify(jwk),
      tokenEndpoint: TOKEN_ENDPOINT,
    });
    expect((await verifyAssertion(params, publicKey)).alg).toBe("ES384");
  });

  it("infers the alg for a JWK that names none", async () => {
    const { privateKey, publicKey } = await keyPair("ES256");
    const params = await buildClientAssertionParams({
      clientId: CLIENT_ID,
      privateKey: JSON.stringify(await exportJWK(privateKey)),
      tokenEndpoint: TOKEN_ENDPOINT,
    });
    expect((await verifyAssertion(params, publicKey)).alg).toBe("ES256");
  });

  it("reports a key that cannot sign under its declared alg", async () => {
    const { privateKey } = await keyPair("ES256");
    const jwk = { ...(await exportJWK(privateKey)), alg: "RS256" };
    await expect(
      buildClientAssertionParams({
        clientId: CLIENT_ID,
        privateKey: JSON.stringify(jwk),
        tokenEndpoint: TOKEN_ENDPOINT,
      }),
    ).rejects.toThrow(/Could not sign a client assertion/);
  });

  it("reports a JWK that declares an unknown alg", async () => {
    const { privateKey } = await keyPair("ES256");
    const jwk = { ...(await exportJWK(privateKey)), alg: "XX999" };
    await expect(
      buildClientAssertionParams({
        clientId: CLIENT_ID,
        privateKey: JSON.stringify(jwk),
        tokenEndpoint: TOKEN_ENDPOINT,
      }),
    ).rejects.toThrow(/Could not sign a client assertion/);
  });
});

describe("parseClientPrivateKey", () => {
  const dashes = "-----";
  const label = ["PRIVATE", "KEY"].join(" ");

  it("rejects malformed JSON", () => {
    expect(() => parseClientPrivateKey("{not json")).toThrow(/not valid JSON/);
  });

  it("rejects a JWK object with no private part", () => {
    expect(() => parseClientPrivateKey("{}")).toThrow(/no private part/);
  });

  it("rejects a public JWK", async () => {
    const { publicKey } = await keyPair("ES256");
    const publicJwk = JSON.stringify(await exportJWK(publicKey));
    expect(() => parseClientPrivateKey(publicJwk)).toThrow(/no private part/);
  });

  it("asks for PKCS#8 when given a SEC1 or PKCS#1 PEM", () => {
    for (const kind of ["EC", "RSA"]) {
      expect(() =>
        parseClientPrivateKey(
          `${dashes}BEGIN ${kind} ${label}${dashes}\nAAAA\n${dashes}END ${kind} ${label}${dashes}`,
        ),
      ).toThrow(/must be PKCS#8 PEM/);
    }
  });

  it("rejects anything that is neither PEM nor JWK", () => {
    expect(() => parseClientPrivateKey("hunter2")).toThrow(
      /PKCS#8 PEM or a private JWK/,
    );
  });

  it("returns a PKCS#8 PEM trimmed", () => {
    const pem = `${dashes}BEGIN ${label}${dashes}\nAAAA\n${dashes}END ${label}${dashes}`;
    expect(parseClientPrivateKey(`  ${pem}\n`)).toBe(pem);
  });
});
