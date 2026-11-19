# Deploying keyferry

keyferry runs on the personal server you administer. Shared machines only open
SSH forwards for the session. No extra port, container, database, or package
daemon is required.

Examples use `personal.example` as a placeholder. Nothing in the program
defaults to a hostname.

## Install

```sh
make build
install -m 0755 keyferry ~/.local/bin/keyferry
keyferry version
```

## State directory

Keys, grants, and token records live in one directory, mode 0700, files mode
0600. The default is `$XDG_STATE_HOME/keyferry`, or `~/.local/state/keyferry`.

```sh
umask 077
mkdir -p ~/.local/state/keyferry
chmod 0700 ~/.local/state/keyferry
```

If that directory is already group or world accessible, keyferry refuses to
start and does not change the mode for you. Back it up only with the same care
as the provider keys.

## Keys and grants

Import a key on the personal server. The key is not a command-line argument.

```sh
umask 077
install -m 0600 /dev/null "$HOME/.config/keyferry-import"
# Put one line in that file, then:
keyferry key add work --provider openai < "$HOME/.config/keyferry-import"
rm -f "$HOME/.config/keyferry-import"
keyferry grant add desk --bind work
keyferry key list
keyferry grant list
```

`openai` and `anthropic` fill in the public HTTPS origin when `--base-url` is
omitted. `generic` needs `--base-url` and `--auth-header`.

A grant may bind several keys. A key may be bound to several grants.
`keyferry grant bind desk --key other` and `grant unbind` edit that list.
`key disable` and `grant disable` fail closed on the next request. Delete does
the same.

Optional extra socket for one grant, then restart serve so it binds:

```sh
keyferry grant edit desk --socket /run/user/"$(id -u)"/keyferry/desk.sock
```

The directory must already be owner-only. `grant edit desk --clear-socket`
removes it.

## Run

Foreground:

```sh
keyferry serve
```

The process prints a `relay` line and a `ui` line. It also prints a `grant`
line for each extra socket. It does not daemonize or write a pid file.

User service, from `deploy/keyferry.service`:

```sh
mkdir -p ~/.config/systemd/user
install -m 0644 deploy/keyferry.service ~/.config/systemd/user/keyferry.service
systemctl --user daemon-reload
systemctl --user enable --now keyferry.service
```

`StateDirectory=keyferry` and `RuntimeDirectory=keyferry` create the state
directory and `/run/user/UID/keyferry` as mode 0700. `UMask=0077` covers
anything else the process creates. To keep the user service up without a
login:

```sh
sudo loginctl enable-linger "$USER"
```

Lingering is optional. Logs stay on the terminal or in the user journal. Do
not redirect them to a world-readable file, and do not put a provider key or a
token in the service environment.

## Admin UI

`serve` opens a second mode-0600 socket, `$XDG_RUNTIME_DIR/keyferry/admin.sock`.
That socket is the only place the management page is served. Shared-machine
clients on the relay socket cannot toggle keys.

On the personal server:

```sh
curl --unix-socket "$XDG_RUNTIME_DIR/keyferry/admin.sock" http://localhost/
```

From a trusted computer, forward only the admin socket:

```sh
ssh -N -L 127.0.0.1:8765:/run/user/REMOTE_UID/keyferry/admin.sock user@personal.example
```

Open `http://127.0.0.1:8765/`. The page can add, edit, delete, and toggle keys
and grants, and bind or unbind them. After save it shows a fingerprint and at
most the last four characters of a long key. Do not forward the admin socket
to a shared machine. `--ui off` disables the page. `--ui tcp:127.0.0.1:PORT`
is loopback on the personal host only.

## Network

keyferry does not bind a routable address. Do not open a firewall port for it.

Clients reach it by SSH. Check sshd if forwards fail:

```text
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
```

Those are OpenSSH defaults. Leave `GatewayPorts` unset. The relay connects out
to providers over HTTPS and ignores `HTTP_PROXY`.

## Shared machines

Several machines, or several routes in one SSH session, share one `serve`
process.

One forward, many grants. `umask 077` matters because ssh creates the local
socket with your umask.

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

`keyferry` here is the placeholder, not a provider key. A second client uses
another prefix, for example `http://localhost/g/other/v1`, on the same socket.
Requests run at the same time.

Several forwards in one session, including a grant that has its own socket:

```sh
umask 077
ssh -N -o ExitOnForwardFailure=yes \
  -L "$XDG_RUNTIME_DIR/keyferry.sock:/run/user/REMOTE_UID/keyferry/relay.sock" \
  -L "$XDG_RUNTIME_DIR/desk.sock:/run/user/REMOTE_UID/keyferry/desk.sock" \
  user@personal.example
```

On `desk.sock` the client can use `http://localhost/v1` with the same
placeholder. The socket already names the grant.

TCP forwards need a token. Other local users can connect to `127.0.0.1`.

```sh
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18080:/run/user/REMOTE_UID/keyferry/relay.sock \
  user@personal.example
```

```sh
# personal server
keyferry token issue --grant desk --ttl 4h --quota 100
```

```sh
export OPENAI_BASE_URL=http://127.0.0.1:18080/g/desk/v1
read -rs OPENAI_API_KEY
export OPENAI_API_KEY
```

`read -rs` keeps the token out of shell history. Do not pass it as a process
argument. Do not set a real provider key on this machine. When the tunnel
drops, the request fails.

`keyferry expose --unix "$XDG_RUNTIME_DIR/keyferry.sock"` is the short-lived
helper when a client can only use TCP and the forward is already a Unix
socket. It exits with the session.

## After the session

On the shared machine, exit SSH. Nothing from keyferry should still be running.
Unset a token if you used TCP, and delete any token file you wrote.

On the personal server, `keyferry token revoke ID` for TCP tokens. Keys stay
in the state directory. Turn a grant off with `keyferry grant disable NAME`
when a route should stop immediately.

## Upgrade and remove

Replace `~/.local/bin/keyferry` and restart the user service. Records already
in the state directory stay. A key file written before the on/off switch is
treated as on until you disable it.

```sh
systemctl --user disable --now keyferry.service
rm -f ~/.config/systemd/user/keyferry.service ~/.local/bin/keyferry
rm -rf ~/.local/state/keyferry
systemctl --user daemon-reload
```

Removing the state directory deletes the provider keys.
