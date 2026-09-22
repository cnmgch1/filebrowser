import { useAuthStore } from "@/stores/auth";
import { renew, logout } from "@/utils/auth";
import { baseURL } from "@/utils/constants";
import {
  buildCredential,
  credentialMaterial,
  encryptBody,
  encryptHeaderValue,
  isStaleEnvelope,
  HandshakeError,
} from "@/utils/credcrypt";
import { encodePath } from "@/utils/url";

export class StatusError extends Error {
  constructor(
    message: any,
    public status?: number,
    public is_canceled?: boolean
  ) {
    super(message);
    this.name = "StatusError";
  }
}

export async function fetchURL(
  url: string,
  opts: ApiOpts,
  auth = true
): Promise<Response> {
  const { encryptedBody, encryptedHeader, ...plain } = opts ?? {};

  // Credentials are single-use and time-bounded: a challenge is spent once, a
  // nonce is spent once, and a timestamp outside the window is refused. A
  // rejected one is therefore rebuilt and sent again, which is what makes a
  // server restart (new key, new challenge) and a skewed client clock heal
  // themselves instead of surfacing as a failed request. One retry only — a
  // second 428 means something else is wrong.
  for (let attempt = 0; ; attempt++) {
    try {
      const request =
        encryptedBody || encryptedHeader
          ? await seal(url, plain, encryptedBody, encryptedHeader)
          : (plain as ApiOpts);

      return await sendRequest(url, request, auth);
    } catch (e) {
      if (attempt === 0 && e instanceof StatusError && isStaleEnvelope(e.status)) {
        continue;
      }
      throw e;
    }
  }
}

/**
 * Builds the encrypted form of a request: the credential goes into an envelope
 * and the caller's other options are carried through unchanged.
 */
async function seal(
  url: string,
  opts: ApiOpts,
  encryptedBody?: { scope: CredentialScope; payload: unknown },
  encryptedHeader?: { name: string; scope: CredentialScope; value: string }
): Promise<ApiOpts> {
  try {
    const headers: Record<string, string> = {
      ...((opts.headers as Record<string, string>) ?? {}),
    };

    if (encryptedHeader) {
      headers[encryptedHeader.name] = await encryptHeaderValue(
        encryptedHeader.scope,
        encryptedHeader.value
      );
    }

    if (!encryptedBody) {
      return { ...opts, headers };
    }

    return {
      ...opts,
      method: opts.method ?? "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify(
        await encryptBody(encryptedBody.scope, encryptedBody.payload)
      ),
    };
  } catch (e) {
    // Failing to encrypt must not silently downgrade to a plaintext credential;
    // surface it as a request error instead.
    throw new StatusError(
      `${url}: ${e instanceof HandshakeError ? e.message : "could not encrypt credentials"}`,
      0
    );
  }
}

export async function sendRequest(
  url: string,
  opts: ApiOpts,
  auth: boolean
): Promise<Response> {
  const authStore = useAuthStore();

  opts = opts || {};
  opts.headers = opts.headers || {};

  const { headers, ...rest } = opts;

  // The token never goes on the wire: every request proves possession of the
  // session key established at login instead. Requests made before a session
  // exists — login, signup — simply carry no credential.
  const material = credentialMaterial();
  const credential = buildCredential(rest.method ?? "GET", material);

  let res;
  try {
    res = await fetch(`${baseURL}${url}`, {
      headers: {
        ...(credential || material.jwt
          ? { "X-Auth": credential || material.jwt }
          : {}),
        ...headers,
      },
      ...rest,
    });
  } catch (e) {
    // Check if the error is an intentional cancellation
    if (e instanceof Error && e.name === "AbortError") {
      throw new StatusError("000 No connection", 0, true);
    }
    throw new StatusError("000 No connection", 0);
  }

  if (auth && res.headers.get("X-Renew-Token") === "true") {
    await renew(authStore.jwt);
  }

  if (res.status < 200 || res.status > 299) {
    const body = await res.text();
    const error = new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );

    if (auth && res.status == 401) {
      logout();
    }

    throw error;
  }

  return res;
}

export async function fetchJSON<T>(url: string, opts?: any): Promise<T> {
  const res = await fetchURL(url, opts);

  if (res.status === 200) {
    return res.json() as Promise<T>;
  }

  throw new StatusError(`${res.status} ${res.statusText}`, res.status);
}

export function removePrefix(url: string): string {
  url = url.split("/").splice(2).join("/");

  if (url === "") url = "/";
  if (url[0] !== "/") url = "/" + url;
  return url;
}

export function createURL(endpoint: string, searchParams = {}): string {
  let prefix = baseURL;
  if (!prefix.endsWith("/")) {
    prefix = prefix + "/";
  }
  const url = new URL(prefix + encodePath(endpoint), origin);
  url.search = new URLSearchParams(searchParams).toString();

  return url.toString();
}

export function setSafeTimeout(callback: () => void, delay: number): number {
  const MAX_DELAY = 86_400_000;
  let remaining = delay;

  function scheduleNext(): number {
    if (remaining <= MAX_DELAY) {
      return window.setTimeout(callback, remaining);
    } else {
      return window.setTimeout(() => {
        remaining -= MAX_DELAY;
        scheduleNext();
      }, MAX_DELAY);
    }
  }

  return scheduleNext();
}
