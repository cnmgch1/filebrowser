import { describe, it, expect, beforeAll, vi } from "vitest";
import { createPinia, setActivePinia } from "pinia";

/**
 * Integration test for the credential-encryption wire format.
 *
 * This is the only test that pins down the browser↔server agreement: the client
 * half below is the real module (@/utils/credcrypt, and the fetchURL plumbing
 * that carries it), and the server half is a real File Browser process.
 *
 * It needs a running server, so it is skipped unless one is pointed at:
 *
 *   FB_E2E_BASE=http://127.0.0.1:18080 \
 *   FB_E2E_USER=admin \
 *   FB_E2E_PASSWORD=... \
 *   pnpm test
 *
 * The server must already contain that user. See the repository notes for the
 * `fb config init` / `fb users add` pair that creates one.
 */

// constants.ts reads window.FileBrowser, which does not exist under vitest's
// node environment; the router would need a DOM for the same reason.
vi.mock("@/utils/constants", () => ({
  baseURL: process.env.FB_E2E_BASE ?? "",
  authMethod: "json",
  noAuth: false,
  logoutPage: "/login",
}));
vi.mock("@/router", () => ({ default: { push: vi.fn() } }));

const { encryptBody, encryptHeaderValue } = await import("@/utils/credcrypt");
const {
  buildCredential,
  credentialMaterial,
  storeCredentialMaterial,
  generateSessionKey,
  readTokenReply,
} = await import("@/utils/credcrypt");
const { fetchURL, StatusError } = await import("@/api/utils");

// The credential material lives in localStorage, which the node test
// environment does not provide.
if (typeof globalThis.localStorage === "undefined") {
  const store = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    value: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, value),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    },
  });
}

const BASE = process.env.FB_E2E_BASE ?? "";
const USER = process.env.FB_E2E_USER ?? "admin";
const PASSWORD = process.env.FB_E2E_PASSWORD ?? "";

const enabled = Boolean(BASE && PASSWORD);
const when = enabled ? describe : describe.skip;

function session(body: unknown): Promise<Response> {
  return fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Auth": "" },
    body: JSON.stringify(body),
  });
}

async function loginBody(username = USER, password = PASSWORD) {
  return encryptBody("login", { username, password, recaptcha: "" });
}

when("credential encryption against a live server", () => {
  beforeAll(() => {
    setActivePinia(createPinia());
  });

  it("encrypts a login body that the server accepts", async () => {
    const body = await loginBody();

    expect(body.encrypted.kid).toBeTruthy();
    expect(body.encrypted.k.length).toBeGreaterThan(0);

    const wire = JSON.stringify(body);
    expect(wire).not.toContain(PASSWORD);
    expect(wire).not.toContain("password");
    expect(wire).toContain("encrypted");

    const res = await session(body);
    expect(res.status).toBe(200);

    // A JWT has three dot-separated segments.
    const token = await res.text();
    expect(token.split(".")).toHaveLength(3);
  });

  it("refuses a replayed envelope", async () => {
    const body = await loginBody();

    expect((await session(body)).status).toBe(200);
    expect((await session(body)).status).toBe(428);
  });

  it("surfaces a spent envelope as a StatusError carrying 428", async () => {
    const body = await loginBody();

    // Burn the envelope, then send it again through the plumbing that decides
    // whether a retry is warranted.
    await session(body);

    const err = await fetchURL(
      "/api/login",
      { method: "POST", body: JSON.stringify(body) },
      false
    ).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(StatusError);
    expect((err as InstanceType<typeof StatusError>).status).toBe(428);

    // 428 is the signal fetchURL uses to rebuild an *encrypted* request; see the
    // encryptedBody path, which is exercised by the live tests above.
  });

  it("sends an encrypted body through the fetchURL plumbing", async () => {
    const res = await fetchURL(
      "/api/login",
      {
        method: "POST",
        encryptedBody: {
          scope: "login",
          payload: { username: USER, password: PASSWORD, recaptcha: "" },
        },
      },
      false
    );

    expect(res.status).toBe(200);
    expect((await res.text()).split(".")).toHaveLength(3);
  });

  it("reports a wrong password as a 403 rather than a decryption failure", async () => {
    const res = await session(await loginBody(USER, "not-the-password-at-all"));
    expect(res.status).toBe(403);
  });

  it("wraps a share password into a prefixed, opaque header value", async () => {
    const header = await encryptHeaderValue("share-unlock", PASSWORD);

    expect(header.startsWith("enc:")).toBe(true);
    expect(header).not.toContain(PASSWORD);

    const parsed = JSON.parse(header.slice("enc:".length));
    expect(parsed.kid).toBeTruthy();
    expect(parsed.d).toBeTruthy();
  });

  it("logs in and then authenticates with a session credential, never the token", async () => {
    const sessionKey = generateSessionKey();

    const login = await fetchURL(
      "/api/login",
      {
        method: "POST",
        encryptedBody: {
          scope: "login",
          payload: { username: USER, password: PASSWORD, recaptcha: "", sessionKey },
        },
      },
      false
    );

    const raw = await login.text();
    expect(login.headers.get("Content-Type")).toContain("application/json");
    // The reply is encrypted, so the token must not be sitting in it in the clear.
    expect(raw).not.toContain("eyJ");

    const reply = readTokenReply(login.headers.get("Content-Type"), raw, sessionKey);
    expect(reply.token.split(".")).toHaveLength(3);
    expect(reply.sealedKey).toBeTruthy();

    storeCredentialMaterial({
      jwt: reply.token,
      sessionKey,
      sealedKey: reply.sealedKey,
    });
    expect(credentialMaterial().sealedKey).toBe(reply.sealedKey);

    // A normal API call now goes out with the v2 credential the request layer
    // builds, and must be accepted.
    const listing = await fetchURL("/api/resources/marker.txt", {});
    expect(listing.status).toBe(200);
  });

  it("builds a credential that carries no token and refuses to be replayed", async () => {
    const current = credentialMaterial();
    expect(current.jwt).toBeTruthy();

    const credential = buildCredential("GET", current);
    expect(credential.startsWith("v2.")).toBe(true);
    expect(credential.split(".")).toHaveLength(5);
    expect(credential).not.toContain(current.jwt);

    const send = () =>
      fetch(`${BASE}/api/resources/marker.txt`, { headers: { "X-Auth": credential } });

    expect((await send()).status).toBe(200);
    expect((await send()).status).toBe(428);
  });
});
