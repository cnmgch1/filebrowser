import { fetchURL, fetchJSON, removePrefix, createURL } from "./utils";

export async function list() {
  return fetchJSON<Share[]>("/api/shares");
}

export async function get(url: string) {
  url = removePrefix(url);
  return fetchJSON<Share>(`/api/share${url}`);
}

export async function remove(hash: string) {
  await fetchURL(`/api/share/${hash}`, {
    method: "DELETE",
  });
}

export async function create(
  url: string,
  password = "",
  expires = "",
  unit = "hours"
) {
  url = removePrefix(url);
  url = `/api/share${url}`;
  if (expires !== "") {
    url += `?expires=${expires}&unit=${unit}`;
  }
  // The body is always sent, even when it carries nothing but defaults: the
  // handler decodes it and rejects a request with no body at all.
  return fetchJSON(url, {
    method: "POST",
    // The share password is a credential too, so it travels in an envelope
    // rather than in a readable body. See @/utils/credcrypt.
    encryptedBody: {
      scope: "share",
      payload: {
        password: password,
        expires: expires.toString(), // backend expects string not number
        unit: unit,
      },
    },
  });
}

export function getShareURL(share: Share) {
  return createURL("share/" + share.hash, {});
}
