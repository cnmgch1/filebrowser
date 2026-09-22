<p align="center">
  <img src="./branding/banner.png" width="550"/>
</p>

File Browser provides a file managing interface within a specified directory: upload, delete, preview and edit files through a web interface. It is a **create-your-own-cloud** kind of software — install it on a server, point it at a path, and reach your files from a browser.

This is a **fork** of [filebrowser/filebrowser](https://github.com/filebrowser/filebrowser), carrying local hardening for deployments that are served over plain HTTP. See [What this fork changes](#what-this-fork-changes) and, more importantly, [Security posture](#security-posture).

## Security posture

**Read this before deploying.** Upstream is archived as of 2026-09-01; there are no further releases, bug fixes, or security fixes from it. Background: [Goodbye File Browser, for Real This Time](https://hacdias.com/2026/07/28/filebrowser/), July 2026.

Published advisories are listed under [security advisories](https://github.com/filebrowser/filebrowser/security/advisories), and reporting instructions are in [SECURITY.md](SECURITY.md).

### What this fork protects

Credentials and session tokens travelling over plain HTTP, against a **passive** eavesdropper — someone who can read traffic on the path but cannot alter it. That threat is real on a LAN, on a shared segment, or through a logging proxy a few hops away, and it is the one thing a password in a POST body is defenceless against.

### What it does not protect

- **An active attacker.** Someone who can rewrite requests or responses, substitute their own public key in the handshake, or inject script into a served page defeats every layer described below. This is not a gap in the implementation: you cannot bootstrap an authenticated channel out of an unauthenticated one.
- **File content.** Files are streamed as they always were. An eavesdropper can read every file that crosses the wire.
- **Token revocation.** Sessions are still self-contained JWTs, so logout, password changes and renewal leave previously issued tokens valid until they expire. Assume a leaked token is valid until expiry.
- **Traffic analysis.** Who fetched what, when, and how much, remains visible.

**If you need any of the above, use TLS.** This fork supports it natively (`--cert` / `--key`, TLS 1.2 minimum) and it is the correct answer wherever it is available. Everything here is a mitigation for the cases where it is not — it is not a substitute.

### Other inherited issues

- **Command execution, runner, and hooks.** Vulnerable across many published advisories and would need a full rewrite to be made safe. Disabled by default; if you re-enable it with `--disableExec=false`, treat the ability to run commands as equivalent to shell access on the host. See [#5199](https://github.com/filebrowser/filebrowser/issues/5199) and [`docs/command-execution.md`](docs/command-execution.md).
- **Session and JWT handling.** See the note on revocation above. [#5216](https://github.com/filebrowser/filebrowser/issues/5216).

If you keep running it, treat it as unmaintained software: run it unprivileged, in a container, with only the directory you intend to serve mounted, and put it behind something that terminates TLS and authenticates on your behalf.

## What this fork changes

Three layers, all aimed at the same threat. None of them changes the HTTP API for existing clients: the CLI, `curl`, and third-party integrations keep sending and receiving what they always did, and a passive attacker cannot force them onto the encrypted path because they cannot rewrite requests.

### Credentials no longer travel in the clear

`/api/login`, `/api/signup`, the user create/update/delete endpoints, share creation, and the share unlock header accept a hybrid envelope in place of the plaintext credential. The client asks for the server's public key and a single-use challenge, seals the payload with a random AES-256-GCM key, and wraps that key with RSA-OAEP (SHA-256).

The challenge is single-use, bound to the operation it was issued for, and expires in two minutes, so captured ciphertext cannot simply be replayed.

### Session tokens stay off the wire

A JWT is a bearer token: anything that reads one can use it. So the browser stops sending it.

At login the client generates a session key and sends it up inside that same envelope. The reply is encrypted under it and returns the token alongside a copy of the session key **sealed under the server's signing key** — which is what lets the server recover the key on any later request without keeping session state, so multi-instance deployments work unchanged.

Every subsequent request proves possession of that key instead of presenting the token:

```
X-Auth: v2.<sealed session key>.<unix seconds>.<nonce>.<AES-GCM(session key, JWT)>
```

The nonce is authenticated by the AEAD, so it cannot be swapped, and the server spends each one exactly once — a captured credential is good for nothing. Requests outside a ±60 second window are refused. A `428` means "rebuild this and try again", which the client does automatically once; a `401` means the session is gone and a fresh login is needed.

### The media cookie is short-lived, opaque, and read-only

Thumbnails, streams and downloads are requested by the browser itself, so they cannot carry a header — the only thing they can present is a cookie. That cookie is necessarily a bearer credential; the goal is to make it cheap to capture. It now holds an opaque sealed blob rather than the JWT, and it is accepted only for `GET`/`HEAD`, only on `/api/raw`, `/api/preview` and `/api/subtitle`, and only for sixty seconds — reissued on every authenticated reply, so it stays fresh while the session is in use and lapses when it is not.

A captured cookie is worth about a minute of read-only media access, against two hours of full account access before.

## Install and run

Grab a release binary, or [build from source](#build-from-source).

```bash
# set up the database and a first user
filebrowser -d filebrowser.db config init
filebrowser -d filebrowser.db users add admin 'a-long-unique-password' --perm.admin

# serve ./files on port 8080
filebrowser -d filebrowser.db -a 0.0.0.0 -p 8080 -r ./files
```

**Use TLS if you possibly can** — it covers the file content and the active-attacker case that nothing in this fork can:

```bash
filebrowser -d filebrowser.db -a 0.0.0.0 -p 443 -r ./files \
  -t /etc/letsencrypt/live/example.com/fullchain.pem \
  -k /etc/letsencrypt/live/example.com/privkey.pem
```

Common options:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-d`, `--database` | `./filebrowser.db` | Database path |
| `-a`, `--address` | `127.0.0.1` | Address to listen on |
| `-p`, `--port` | `8080` | Port to listen on |
| `-r`, `--root` | `.` | Directory to serve |
| `-t`, `--cert` | | TLS certificate |
| `-k`, `--key` | | TLS key |
| `--tokenExpirationTime` | `2h` | Session lifetime |
| `--disableExec` | `true` | Leave the command runner off |

Run `filebrowser --help` for the rest, or see [`docs`](docs).

## Build from source

Requires **Go 1.25+**, **Node 24+** and **pnpm 10+**.

The frontend assets are embedded into the Go binary, and `frontend/dist` is **empty in a fresh clone** — the frontend has to be built before the backend, or you get a binary with no UI:

```bash
# 1. frontend
cd frontend
pnpm install --frozen-lockfile
pnpm run build          # writes frontend/dist

# 2. backend
cd ..
go build -o filebrowser .
```

[Taskfile.yml](Taskfile.yml) wraps the same two steps as `task build`. [CONTRIBUTING.md](CONTRIBUTING.md) covers development, which remains useful to anyone forking this.

### Tests

```bash
go test ./...                          # backend
cd frontend && pnpm test               # frontend
```

A handful of tests in `files` and `http` fail on Windows, from `truncate` and path semantics rather than anything in the code; they pass on Linux and macOS.

The frontend integration test in [`frontend/src/utils/__tests__/credcrypt.integration.test.ts`](frontend/src/utils/__tests__/credcrypt.integration.test.ts) exercises the wire format against a real server and is skipped unless one is pointed at:

```bash
FB_E2E_BASE=http://127.0.0.1:8080 \
FB_E2E_USER=admin \
FB_E2E_PASSWORD='a-long-unique-password' \
pnpm test
```

## Documentation

How to install, configure and deploy lives in [`docs`](docs) in this repository.

## License

[Apache License 2.0](LICENSE) © File Browser Contributors. This fork keeps the upstream license and attribution; the hardening described above is additional to upstream and carries no warranty of its own.
