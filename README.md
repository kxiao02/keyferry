# keyferry

keyferry is a small relay for LLM API calls. Provider keys stay on a personal
server you administer. A shared machine reaches that server through SSH and
never sees a provider key.

One static binary serves every grant at once. It does not need a database, a
dashboard, a container, or a second process.

## Threat model

Trusted: you, on the personal server, with the provider keys.

Not trusted: other users on a shared machine, anyone who can read process
arguments or world-readable files, and the network beyond the SSH tunnel.

What keyferry enforces:

- Provider keys live in mode-0600 files and are injected only on the personal
  server, on the connection to the provider.
- The relay listens on one user-owned Unix socket, mode 0600. A grant can
  optionally listen on its own extra Unix socket. The admin UI uses a different
  socket and is not mounted on the relay socket.
- keyferry refuses to start if a socket, the state directory, or a secret file
  is group or world accessible. If a socket's mode changes later, the process
  stops.
- On the Unix socket, the client api key is the fixed placeholder `keyferry`.
  That word is not a secret. The socket is the authenticator. Turning a grant
  or all of its keys off fails the next request.
- TCP listen and TCP forwards require a short-lived relay token. The
  placeholder is rejected there, so another local user cannot ride an open
  switch.
- A request names its grant with the path prefix `/g/NAME/...` or the header
  `X-Keyferry-Grant`. One SSH forward can carry several grants at once. If you
  omit the name and exactly one grant is enabled, that grant is used. If more
  than one is enabled, the request fails until it names one.
- The chosen grant must be on, and at least one bound key must be on. Otherwise
  the request fails. Requests are not queued behind each other.
- `HTTP_PROXY` is ignored. Cleartext upstreams are refused except to loopback.
- Bodies, prompts, tokens, and provider keys are not logged. There is no telemetry.

## Build

Go 1.22 or newer.

```sh
make build
make test
```

`CGO_ENABLED=0` keeps the binary static.

## Personal server

```sh
install -m 0755 keyferry ~/.local/bin/keyferry
umask 077
keyferry key add work --provider openai < /path/to/keyfile
rm -f /path/to/keyfile
keyferry grant add desk --bind work
keyferry serve
```

`serve` prints the relay socket and the admin socket. Both are mode 0600 under
`$XDG_RUNTIME_DIR/keyferry/` when that directory exists. Stop the process with
SIGINT, SIGTERM, or SIGHUP. A user service is in `deploy/keyferry.service`.
See [DEPLOY.md](DEPLOY.md).

Keys and grants can be on or off:

```sh
keyferry key disable work
keyferry key enable work
keyferry grant disable desk
```

`key edit NAME --rotate` reads a replacement key from stdin. `grant bind` and
`grant unbind` change which keys a grant may use. One key can be bound to
several grants, and one grant can bind several keys. The relay picks the first
enabled bound key in name order.

### Admin UI

The UI is part of `keyferry serve`. It is a single page: add, edit, delete,
and toggle keys and grants, and bind or unbind keys. It does not show a full
key after save (a fingerprint and, for long keys, the last four characters).

Open it on the personal server, not on a shared machine:

```sh
# the socket path is the "ui" line from keyferry serve
curl --unix-socket "$XDG_RUNTIME_DIR/keyferry/admin.sock" http://localhost/
```

A browser needs a loopback TCP port. Forward only the admin socket, and only
to a machine you trust:

```sh
ssh -N -L 127.0.0.1:8765:"$XDG_RUNTIME_DIR/keyferry/admin.sock" user@personal.example
```

Then open `http://127.0.0.1:8765/`. Do not forward that port onto a shared
machine. `--ui off` disables the page. `--ui tcp:127.0.0.1:PORT` binds loopback
on the personal host. A public address is refused.

Adding a key in the form is a POST body. The page never puts the key in a query
string or echoes it back.

## Shared machine

Do not copy the state directory, and do not run `serve` here.

One forward, several grants. `umask 077` so the local socket is owner-only.
Point each client at a path prefix. The api key is the placeholder, not a
provider key and not a relay token.

```sh
umask 077
ssh -N -o ExitOnForwardFailure=yes \
  -L "$XDG_RUNTIME_DIR/keyferry.sock:/run/user/REMOTE_UID/keyferry/relay.sock" \
  user@personal.example
```

```sh
export OPENAI_BASE_URL=http://localhost/g/desk/v1
export OPENAI_API_KEY=keyferry
```

A second client can use `http://localhost/g/other/v1` through the same socket
at the same time. If a grant has its own socket (`keyferry grant edit NAME
--socket /run/user/UID/keyferry/NAME.sock`, then restart `serve`), forward that
socket too:

```sh
umask 077
ssh -N -o ExitOnForwardFailure=yes \
  -L "$XDG_RUNTIME_DIR/keyferry.sock:/run/user/REMOTE_UID/keyferry/relay.sock" \
  -L "$XDG_RUNTIME_DIR/desk.sock:/run/user/REMOTE_UID/keyferry/desk.sock" \
  user@personal.example
```

On a grant's own socket the path prefix is optional. Two shared machines can
each open their own SSH session to the same relay.

Loopback TCP (`ssh -L 127.0.0.1:PORT:...` or `keyferry expose`) is visible to
other users on that machine. Use a relay token there, not the placeholder:

```sh
# on the personal server
keyferry token issue --grant desk --ttl 4h
```

```sh
export OPENAI_BASE_URL=http://127.0.0.1:18080/g/desk/v1
read -rs OPENAI_API_KEY
export OPENAI_API_KEY
```

Do not put the token on a command line. Do not configure a real provider key
as a fallback. When SSH exits, the local socket or port is gone and requests
fail. Revoke TCP tokens with `keyferry token revoke ID`.

`keyferry expose` is only when a client cannot speak HTTP over a Unix socket
and you already have one locally. It exits with the session and leaves no pid
file or log.

## Commands

```text
keyferry serve [--listen unix:PATH|tcp:ADDR] [--ui unix:PATH|tcp:ADDR|off]
keyferry key add|edit|list|remove|enable|disable
keyferry grant add|edit|list|remove|enable|disable|bind|unbind
keyferry token issue|list|revoke
keyferry expose --unix PATH
```

`upstream` is an alias of `key`. `entry` is an alias of `grant`.
`--verbose` logs status, grant names, and token ids. It does not log bodies,
prompts, tokens, or provider keys.

## Limitations

- The placeholder is safe only on an owner-only Unix socket. On TCP it is rejected.
- With several enabled grants, a request that names none of them fails.
- Revoke and the off switch stop new requests. A response already streaming continues.
- Request quota on a token is counted when the request is accepted.
- The provider key is in process memory and in the state file. Disk encryption
  is your job.
- If the personal server or the tunnel is down, calls fail. There is no second key
  tried after a provider error.
- OpenAI-compatible and Anthropic clients work by changing the base URL. Other
  vendors need `--provider generic` and one auth header.
