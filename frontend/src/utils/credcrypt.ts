import forge from "node-forge";
import { baseURL } from "./constants";

/**
 * Credential encryption for File Browser deployments served over plain HTTP.
 *
 * ## Why this exists
 *
 * A login POST carries a password. Over `http://` that password is readable by
 * anyone able to watch the connection — a shared Wi-Fi segment, a mirroring
 * switch port, a logging reverse proxy. TLS is the real answer, but a file
 * server on a home or office LAN often cannot have it, and the password people
 * type there is usually the one they reuse elsewhere.
 *
 * ## How it works
 *
 * 1. The client asks `/api/crypto/handshake` for the server's ephemeral RSA
 *    public key and a single-use challenge for the operation it is about to
 *    perform.
 * 2. It generates a random AES-256-GCM key, seals the request payload with it,
 *    and wraps that key with RSA-OAEP (SHA-256) under the server's key.
 * 3. It POSTs `{"encrypted": {kid, k, iv, d}}` in place of the plaintext body.
 *
 * Only the server can unwrap the payload, so the password is never on the wire.
 * The challenge inside the sealed payload is what stops the ciphertext from
 * being replayed verbatim by the same passive attacker who captured it: it is
 * accepted exactly once, only for the scope it was issued for, and only until it
 * expires.
 *
 * ## Why node-forge and not WebCrypto
 *
 * `crypto.subtle` is only exposed in a *secure context*. `http://localhost`
 * qualifies, but `http://192.168.1.10:8080` — the deployment this whole module
 * exists for — does not. WebCrypto is therefore unavailable exactly where it is
 * needed, so the primitives come from a bundled pure-JS library instead. This
 * costs some bundle size; it is the price of working on the deployments that
 * need it.
 *
 * ## What this does not protect
 *
 * The session token the server returns after login, and every other byte of
 * every response, still travel in the clear. Deploy behind HTTPS where that is
 * possible.
 */

interface Handshake {
  algorithm: string;
  keyID: string;
  key: string;
  challenge: string;
  expiresIn: number;
}

/** The encrypted replacement for a request body, as it goes on the wire. */
export interface Envelope {
  kid: string;
  k: string;
  iv: string;
  d: string;
}

export interface EncryptedBody {
  encrypted: Envelope;
}

const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BITS = 128;

/**
 * Raised when the handshake itself fails, i.e. before any credential has been
 * sent. The API layer turns this into a StatusError so the UI reports it
 * normally.
 */
export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeError";
  }
}

/**
 * Fetches a public key and a challenge for one operation.
 *
 * A fresh challenge is required for every request, so this is deliberately not
 * cached; the key could be, but the round trip is what makes replay detection
 * possible and it costs one small request next to the login it protects.
 */
async function handshake(scope: string): Promise<Handshake> {
  const res = await fetch(`${baseURL}/api/crypto/handshake`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope }),
  });

  if (!res.ok) {
    throw new HandshakeError(
      `credential handshake failed: ${res.status} ${res.statusText}`
    );
  }

  const data = (await res.json()) as Handshake;
  if (!data.key || !data.challenge) {
    throw new HandshakeError("credential handshake returned no key");
  }

  return data;
}

/**
 * Rebuilds a forge public key from the base64 SubjectPublicKeyInfo the server
 * hands out — the same encoding `x509.MarshalPKIXPublicKey` produces.
 */
function parsePublicKey(spkiBase64: string): forge.pki.rsa.PublicKey {
  const der = forge.util.decode64(spkiBase64);
  const asn1 = forge.asn1.fromDer(der);
  const key = forge.pki.publicKeyFromAsn1(asn1);

  if (typeof key === "string") {
    throw new HandshakeError("server sent an unsupported public key");
  }

  return key;
}

/**
 * Seals `payload` for the given scope and returns the envelope to send in its
 * place.
 */
export async function encryptBody(
  scope: string,
  payload: unknown
): Promise<EncryptedBody> {
  const { keyID, key, challenge } = await handshake(scope);
  const publicKey = parsePublicKey(key);

  const aesKey = forge.random.getBytesSync(AES_KEY_BYTES);
  const iv = forge.random.getBytesSync(GCM_NONCE_BYTES);

  const cipher = forge.cipher.createCipher("AES-GCM", aesKey);
  cipher.start({ iv, tagLength: GCM_TAG_BITS });
  cipher.update(
    forge.util.createBuffer(
      forge.util.encodeUtf8(JSON.stringify({ challenge, payload }))
    )
  );

  if (!cipher.finish()) {
    throw new HandshakeError("failed to encrypt the request payload");
  }

  // Go's cipher.AEAD expects the tag appended to the ciphertext.
  const sealed = cipher.output.getBytes() + cipher.mode.tag.getBytes();

  const wrappedKey = publicKey.encrypt(aesKey, "RSA-OAEP", {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha256.create() },
  });

  return {
    encrypted: {
      kid: keyID,
      k: forge.util.encode64(wrappedKey),
      iv: forge.util.encode64(iv),
      d: forge.util.encode64(sealed),
    },
  };
}

/**
 * Encrypts a single secret for transport in a header, such as a share's
 * `X-SHARE-PASSWORD`. The wire form is the literal prefix `enc:` followed by the
 * envelope as JSON, which base64 cannot be confused with.
 */
export async function encryptHeaderValue(
  scope: string,
  value: string
): Promise<string> {
  const body = await encryptBody(scope, { value });
  return `enc:${JSON.stringify(body.encrypted)}`;
}

/**
 * True when the server rejected an envelope that needs to be rebuilt: either the
 * challenge was already used or has expired, or the public key changed under us
 * (the key pair is ephemeral, so a server restart invalidates cached keys).
 */
export function isStaleEnvelope(status: number | undefined): boolean {
  return status === 428;
}

/* ------------------------------------------------------------------ sessions
 *
 * A JWT is a bearer token: anyone who reads one off the wire can use it. So the
 * browser stops sending it. At login it generates a session key, sends it up
 * inside the already encrypted login envelope, and gets back an encrypted reply
 * carrying the token and a *sealed* copy of that session key. From then on every
 * request proves possession of the session key instead of presenting the token:
 *
 *   v2.<sealed session key>.<unix seconds>.<nonce>.<AES-GCM(session key, JWT)>
 *
 * Nothing in that header can be turned into a usable credential by someone who
 * captured it. The session key is inside the sealed blob, which only the server
 * can open; the nonce is part of the AEAD's additional data, so it cannot be
 * swapped; and the server spends each nonce exactly once, so the ciphertext
 * cannot be replayed.
 *
 * This is a defence against a passive eavesdropper. It does nothing against an
 * active attacker — see the package note above.
 * ------------------------------------------------------------------------- */

const JWT_STORAGE_KEY = "jwt";
const SESSION_KEY_STORAGE_KEY = "sessionKey";
const SEALED_KEY_STORAGE_KEY = "sealedKey";

const SESSION_KEY_BYTES = 32;
const CREDENTIAL_NONCE_BYTES = 12;
const CREDENTIAL_AAD_PREFIX = "filebrowser/credential/v1\n";
const RESPONSE_AAD = "filebrowser/session-response/v1";

/** What the client needs to authenticate a request. */
export interface CredentialMaterial {
  jwt: string;
  sessionKey: string;
  sealedKey: string;
}

/** A freshly generated session key, base64, as the login payload carries it. */
export function generateSessionKey(): string {
  return forge.util.encode64(forge.random.getBytesSync(SESSION_KEY_BYTES));
}

/** The credential material currently in storage, empty strings when absent. */
export function credentialMaterial(): CredentialMaterial {
  return {
    jwt: localStorage.getItem(JWT_STORAGE_KEY) ?? "",
    sessionKey: localStorage.getItem(SESSION_KEY_STORAGE_KEY) ?? "",
    sealedKey: localStorage.getItem(SEALED_KEY_STORAGE_KEY) ?? "",
  };
}

export function storeCredentialMaterial(material: CredentialMaterial) {
  localStorage.setItem(JWT_STORAGE_KEY, material.jwt);
  localStorage.setItem(SESSION_KEY_STORAGE_KEY, material.sessionKey);
  localStorage.setItem(SEALED_KEY_STORAGE_KEY, material.sealedKey);
}

export function clearCredentialMaterial() {
  localStorage.setItem(JWT_STORAGE_KEY, "");
  localStorage.setItem(SESSION_KEY_STORAGE_KEY, "");
  localStorage.setItem(SEALED_KEY_STORAGE_KEY, "");
}

/** base64url without padding, matching Go's base64.RawURLEncoding. */
function toBase64Url(value: string): string {
  return forge.util.encode64(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes a base64 session key into the raw key bytes forge works with. */
function sessionCipher(sessionKeyBase64: string): string {
  return forge.util.decode64(sessionKeyBase64);
}

/**
 * Builds the v2 credential for one request, or "" when there is nothing to
 * authenticate with.
 *
 * The method is bound into the tag, so a credential minted for a read cannot be
 * pointed at a write. The exact request target deliberately is not: reconciling
 * the browser's URL serialiser with Go's would make any filename containing an
 * unusual character fail to authenticate, and the nonce already rules out reuse.
 */
export function buildCredential(method: string, material: CredentialMaterial): string {
  if (!material.jwt || !material.sessionKey || !material.sealedKey) {
    return "";
  }

  const key = sessionCipher(material.sessionKey);
  const nonce = forge.random.getBytesSync(CREDENTIAL_NONCE_BYTES);
  const nonceText = toBase64Url(nonce);
  const issuedAt = Math.floor(Date.now() / 1000);

  const cipher = forge.cipher.createCipher("AES-GCM", key);
  cipher.start({
    iv: nonce,
    tagLength: 128,
    additionalData: `${CREDENTIAL_AAD_PREFIX}${method}\n${issuedAt}\n${nonceText}`,
  });
  cipher.update(forge.util.createBuffer(material.jwt));

  if (!cipher.finish()) {
    throw new HandshakeError("failed to build the request credential");
  }

  const ciphertext = cipher.output.getBytes() + cipher.mode.tag.getBytes();

  return [
    "v2",
    material.sealedKey,
    issuedAt,
    nonceText,
    forge.util.encode64(ciphertext),
  ].join(".");
}

/** A token reply, as the server sends it: an envelope over the session key. */
interface EncryptedTokenReply {
  encrypted: { iv: string; d: string };
}

function isEncryptedReply(value: unknown): value is EncryptedTokenReply {
  const candidate = value as EncryptedTokenReply | null;
  return Boolean(candidate?.encrypted?.iv && candidate.encrypted.d);
}

/**
 * Reads a token reply, decrypting it when the server encrypted it.
 *
 * A client that sent no session key still gets a plaintext token, which is what
 * keeps the CLI and third-party clients working.
 */
export function readTokenReply(
  contentType: string | null,
  body: string,
  sessionKey: string
): { token: string; sealedKey: string } {
  if (!contentType?.includes("application/json")) {
    return { token: body, sealedKey: "" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new HandshakeError("the server sent an unreadable token reply");
  }

  if (!isEncryptedReply(parsed)) {
    return { token: body, sealedKey: "" };
  }

  const key = sessionCipher(sessionKey);
  const iv = forge.util.decode64(parsed.encrypted.iv);
  const sealed = forge.util.decode64(parsed.encrypted.d);

  // Go's cipher.AEAD appends the tag to the ciphertext.
  const tagLength = 16;
  const tag = sealed.slice(sealed.length - tagLength);
  const ciphertext = sealed.slice(0, sealed.length - tagLength);

  const decipher = forge.cipher.createDecipher("AES-GCM", key);
  decipher.start({
    iv,
    tagLength: 128,
    tag: forge.util.createBuffer(tag),
    additionalData: RESPONSE_AAD,
  });
  decipher.update(forge.util.createBuffer(ciphertext));

  if (!decipher.finish()) {
    throw new HandshakeError("the server's token reply did not authenticate");
  }

  const payload = JSON.parse(decipher.output.toString()) as {
    token: string;
    sealedKey: string;
  };

  return { token: payload.token, sealedKey: payload.sealedKey };
}
