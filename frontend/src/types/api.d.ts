type ApiMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";

type ApiContent =
  | Blob
  | File
  | Pick<ReadableStreamDefaultReader<any>, "read">
  | "";

/**
 * An operation that carries a credential and therefore has an encrypted form.
 * Must stay in step with the scope list in the Go package `credcrypt` and with
 * `credentialScopes` in `http/credcrypt.go`.
 */
type CredentialScope =
  | "login"
  | "signup"
  | "users"
  | "share"
  | "share-unlock";

interface ApiOpts {
  method?: ApiMethod;
  headers?: object;
  body?: any;
  signal?: AbortSignal;
  /**
   * Send `payload` as an encrypted body instead of `body`, so the credential it
   * carries is not readable on the wire. See @/utils/credcrypt.
   */
  encryptedBody?: { scope: CredentialScope; payload: unknown };
  /**
   * Send `value` as an encrypted header instead of a literal one.
   */
  encryptedHeader?: { name: string; scope: CredentialScope; value: string };
}

interface TusSettings {
  retryCount: number;
  chunkSize: number;
}

type ChecksumAlg = "md5" | "sha1" | "sha256" | "sha512";

interface Share {
  hash: string;
  path: string;
  expire?: any;
  userID?: number;
  hasPassword?: boolean;
  username?: string;
}

interface SearchParams {
  [key: string]: string;
}
