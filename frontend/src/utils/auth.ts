import { useAuthStore } from "@/stores/auth";
import router from "@/router";
import type { JwtPayload } from "jwt-decode";
import { jwtDecode } from "jwt-decode";
import { authMethod, baseURL, noAuth, logoutPage } from "./constants";
import { fetchURL, StatusError } from "@/api/utils";
import { setSafeTimeout } from "@/api/utils";
import {
  buildCredential,
  clearCredentialMaterial,
  credentialMaterial,
  generateSessionKey,
  readTokenReply,
  storeCredentialMaterial,
} from "./credcrypt";

export function parseToken(token: string, sealedKey = "", sessionKey = "") {
  // falsy or malformed jwt will throw InvalidTokenError
  const data = jwtDecode<JwtPayload & { user: IUser }>(token);

  // The `auth` cookie is issued by the server, not written here. It holds a
  // short-lived, opaque media credential rather than the token itself, so
  // putting the token in it — as this used to — would hand an eavesdropper a
  // two hour account credential from any thumbnail request. See http/session.go.
  storeCredentialMaterial({ jwt: token, sealedKey, sessionKey });

  const authStore = useAuthStore();
  authStore.jwt = token;
  authStore.setUser(data.user);

  // proxy auth with custom logout subject to unknown external timeout
  if (logoutPage !== "/login" && authMethod === "proxy") {
    console.warn("idle timeout disabled with proxy auth and custom logout");
    return;
  }

  if (authStore.logoutTimer) {
    clearTimeout(authStore.logoutTimer);
  }

  const expiresAt = new Date(data.exp! * 1000);
  const timeout = expiresAt.getTime() - Date.now();
  authStore.setLogoutTimer(
    setSafeTimeout(() => {
      logout("inactivity");
    }, timeout)
  );
}

export async function validateLogin() {
  try {
    if (localStorage.getItem("jwt")) {
      await renew(<string>localStorage.getItem("jwt"));
    }
  } catch (error) {
    console.warn("Invalid JWT token in storage");
    throw error;
  }
}

export async function login(
  username: string,
  password: string,
  recaptcha: string
) {
  // A fresh session key per login: the reply is encrypted under it, and every
  // later request proves possession of it instead of presenting the token.
  const sessionKey = generateSessionKey();

  // The credentials go inside an envelope, so the password is not readable by
  // anyone watching the connection. See @/utils/credcrypt.
  const res = await fetchURL(
    "/api/login",
    {
      method: "POST",
      encryptedBody: {
        scope: "login",
        payload: { username, password, recaptcha, sessionKey },
      },
    },
    false
  );

  const body = await res.text();
  const reply = readTokenReply(res.headers.get("Content-Type"), body, sessionKey);

  parseToken(reply.token, reply.sealedKey, sessionKey);
}

export async function renew(jwt: string) {
  const material = credentialMaterial();
  const credential = buildCredential("POST", { ...material, jwt: material.jwt || jwt });

  const res = await fetch(`${baseURL}/api/renew`, {
    method: "POST",
    headers: {
      "X-Auth": credential,
    },
  });

  const body = await res.text();

  if (res.status === 200) {
    // The reply is encrypted with the session key we already hold, so we can
    // read it without a handshake.
    const reply = readTokenReply(
      res.headers.get("Content-Type"),
      body,
      material.sessionKey
    );
    parseToken(reply.token, reply.sealedKey, material.sessionKey);
  } else {
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export async function signup(username: string, password: string) {
  await fetchURL(
    "/api/signup",
    {
      method: "POST",
      encryptedBody: {
        scope: "signup",
        payload: { username, password },
      },
    },
    false
  );
}

export function logout(reason?: string) {
  document.cookie = "auth=; Max-Age=0; Path=/; SameSite=Strict;";

  const authStore = useAuthStore();
  authStore.clearUser();

  clearCredentialMaterial();
  if (noAuth) {
    window.location.reload();
  } else if (logoutPage !== "/login") {
    document.location.href = `${logoutPage}`;
  } else {
    if (typeof reason === "string" && reason.trim() !== "") {
      router.push({
        path: "/login",
        query: { "logout-reason": reason },
      });
    } else {
      router.push({
        path: "/login",
      });
    }
  }
}
