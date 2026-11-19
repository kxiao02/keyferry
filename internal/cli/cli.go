// Package cli is the keyferry command line.
// Provider keys and relay tokens are never accepted as flags, so they stay out of argv.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"keyferry/internal/expose"
	"keyferry/internal/perms"
	"keyferry/internal/serve"
	"keyferry/internal/store"
)

// Version is the release stamped into `keyferry version`.
var Version = "0.1.0"

// Run executes one invocation. It returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "keyferry %s\n", Version)
		return 0
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "expose":
		return cmdExpose(args[1:], stdin, stdout, stderr)
	case "key", "upstream":
		return cmdUpstream(args[1:], stdin, stdout, stderr)
	case "grant", "entry":
		return cmdGrant(args[1:], stdout, stderr)
	case "token":
		return cmdToken(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "keyferry: unknown command %q\n", args[0])
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state-dir", "", "state directory (default: XDG state dir)")
	listenSpec := fs.String("listen", "", "unix:/abs/path or tcp:127.0.0.1:port")
	uiSpec := fs.String("ui", "", "admin socket spec, or off")
	verbose := fs.Bool("verbose", false, "log status and token ids, never bodies or secrets")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(stderr, "keyferry: serve takes no positional arguments")
		return 2
	}
	dir, err := resolveState(*state)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	spec := *listenSpec
	if spec == "" {
		spec = os.Getenv("KEYFERRY_LISTEN")
	}
	var verboseOut io.Writer
	if *verbose {
		verboseOut = stderr
	}
	ctx, cancel := signalContext()
	defer cancel()
	err = serve.Serve(ctx, serve.Options{
		StateDir: dir,
		Listen:   spec,
		UI:       *uiSpec,
		Verbose:  verboseOut,
		Alerts:   stderr,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	_ = stdout
	return 0
}

func cmdExpose(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("expose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	unixPath := fs.String("unix", "", "forwarded unix socket")
	tcpAddr := fs.String("listen", "127.0.0.1:0", "loopback host:port")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 || *unixPath == "" {
		fmt.Fprintln(stderr, "keyferry: expose requires --unix")
		return 2
	}
	ctx, cancel := signalContext()
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, stdin)
		cancel()
	}()
	go watchParent(ctx, cancel)
	if err := expose.Run(ctx, *unixPath, *tcpAddr, stdout); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	return 0
}

func cmdUpstream(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "keyferry: key requires add, edit, list, remove, enable, or disable")
		return 2
	}
	switch args[0] {
	case "add":
		return cmdUpstreamAdd(args[1:], stdin, stdout, stderr)
	case "edit":
		return cmdKeyEdit(args[1:], stdin, stdout, stderr)
	case "list":
		return cmdUpstreamList(args[1:], stdout, stderr)
	case "remove", "rm", "delete":
		return cmdUpstreamRemove(args[1:], stdout, stderr)
	case "enable":
		return cmdKeyEnabled(args[1:], true, stdout, stderr)
	case "disable":
		return cmdKeyEnabled(args[1:], false, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "keyferry: key requires add, edit, list, remove, enable, or disable")
		return 2
	}
}

func cmdUpstreamAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upstream add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	provider := fs.String("provider", "", "openai, anthropic, or generic")
	base := fs.String("base-url", "", "origin URL, https except loopback http")
	authHeader := fs.String("auth-header", "", "generic provider header name")
	authScheme := fs.String("auth-scheme", "", "optional generic scheme, such as Bearer")
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 || *provider == "" {
		fmt.Fprintln(stderr, "keyferry: usage: upstream add NAME --provider openai|anthropic|generic")
		return 2
	}
	key, err := readSecret(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	dir, err := resolveState(*state)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	st, err := store.Open(dir)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	err = st.PutUpstream(store.Upstream{
		Name:       positionals[0],
		Provider:   *provider,
		BaseURL:    *base,
		AuthHeader: *authHeader,
		AuthScheme: *authScheme,
		Key:        key,
	})
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "upstream\t%s\n", positionals[0])
	return 0
}

func cmdUpstreamList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upstream list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(stderr, "keyferry: upstream list takes no names")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	list, err := st.ListUpstreams()
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintln(stdout, "name\tprovider\tbase_url\tenabled\tkey_fp\tlast4")
	for _, item := range list {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%t\t%s\t%s\n", item.Name, item.Provider, item.BaseURL, item.Enabled, item.KeyFP, item.Last4)
	}
	return 0
}

func cmdUpstreamRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upstream remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: upstream remove NAME")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.DeleteUpstream(positionals[0]); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "removed\t%s\n", positionals[0])
	return 0
}

func cmdToken(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "keyferry: token requires issue, list, or revoke")
		return 2
	}
	switch args[0] {
	case "issue":
		return cmdTokenIssue(args[1:], stdout, stderr)
	case "list":
		return cmdTokenList(args[1:], stdout, stderr)
	case "revoke":
		return cmdTokenRevoke(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "keyferry: token requires issue, list, or revoke")
		return 2
	}
}

func cmdTokenIssue(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	grant := fs.String("grant", "", "grant name")
	upstream := fs.String("upstream", "", "grant name (alias of --grant)")
	ttlFlag := fs.String("ttl", "4h", "lifetime, maximum 168h")
	quota := fs.Int("quota", 0, "request budget; 0 means unlimited")
	label := fs.String("label", "", "note stored beside the token")
	outPath := fs.String("out", "", "write the token to a new mode-0600 file")
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	grantName := *grant
	if grantName == "" {
		grantName = *upstream
	}
	if len(positionals) != 0 || grantName == "" {
		fmt.Fprintln(stderr, "keyferry: usage: token issue --grant NAME [--ttl 4h] [--quota N] [--label TEXT] [--out FILE]")
		return 2
	}
	ttl, err := time.ParseDuration(*ttlFlag)
	if err != nil {
		fmt.Fprintln(stderr, "keyferry: invalid --ttl")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	raw, rec, err := st.IssueToken(grantName, *label, ttl, *quota)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	if *outPath != "" {
		if err := writeExclusive(*outPath, raw+"\n"); err != nil {
			_ = st.Revoke(rec.ID)
			fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
			return 1
		}
		fmt.Fprintf(stdout, "id=%s\ngrant=%s\nexpires=%s\nout=%s\n", rec.ID, rec.GrantName(), rec.Expires.Format(time.RFC3339), *outPath)
		return 0
	}
	fmt.Fprintf(stdout, "id=%s\ngrant=%s\nexpires=%s\ntoken=%s\n", rec.ID, rec.GrantName(), rec.Expires.Format(time.RFC3339), raw)
	return 0
}

func cmdTokenList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(stderr, "keyferry: token list takes no ids")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	list, err := st.ListTokens()
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintln(stdout, "id\tgrant\texpires\trevoked\tquota_remaining\tlabel")
	for _, item := range list {
		quota := "-"
		if item.QuotaRemaining != nil {
			quota = fmt.Sprintf("%d", *item.QuotaRemaining)
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%t\t%s\t%s\n",
			item.ID, item.GrantName(), item.Expires.Format(time.RFC3339), item.Revoked, quota, item.Label)
	}
	return 0
}

func cmdTokenRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: token revoke ID")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.Revoke(positionals[0]); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "revoked\t%s\n", positionals[0])
	return 0
}

// parseMixed accepts flags before or after positional arguments.
// The standard flag parser stops at the first positional, which rejects
// `upstream add NAME --provider openai`.
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags []string
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(arg) > 1 && arg[0] == '-' {
			flags = append(flags, arg)
			name := strings.TrimLeft(arg, "-")
			if strings.Contains(name, "=") {
				continue
			}
			if takesValue(fs, name) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, arg)
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return pos, nil
}

func takesValue(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return true
	}
	type boolFlag interface{ IsBoolFlag() bool }
	if b, ok := f.Value.(boolFlag); ok && b.IsBoolFlag() {
		return false
	}
	return true
}

func openState(flagValue string, stderr io.Writer) (*store.Store, int) {
	dir, err := resolveState(flagValue)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return nil, 1
	}
	st, err := store.Open(dir)
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return nil, 1
	}
	return st, 0
}

func resolveState(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return store.DefaultDir()
}

func readSecret(stdin io.Reader) (string, error) {
	buf, err := io.ReadAll(io.LimitReader(stdin, 8192))
	if err != nil {
		return "", err
	}
	if int64(len(buf)) >= 8192 {
		return "", errors.New("refusing an oversized secret")
	}
	key := strings.TrimRight(string(buf), "\r\n")
	if key == "" {
		return "", errors.New("provider key was empty; pass it on stdin, not as a flag")
	}
	return key, nil
}

func writeExclusive(path, data string) error {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("refusing to write token file")
	}
	f := os.NewFile(uintptr(fd), path)
	_, werr := f.Write([]byte(data))
	cerr := f.Close()
	if werr != nil {
		os.Remove(path)
		return errors.New("could not write token file")
	}
	if cerr != nil {
		os.Remove(path)
		return errors.New("could not write token file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		os.Remove(path)
		return err
	}
	if err := perms.AssertOwnerOnly(path, false); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signalNotifyContext()
}

func watchParent(ctx context.Context, cancel context.CancelFunc) {
	ppid := os.Getppid()
	if ppid <= 1 {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if os.Getppid() != ppid {
				cancel()
				return
			}
		}
	}
}

const usage = `keyferry relays LLM API calls so provider keys stay on your personal server.

Default access is a mode-0600 Unix socket plus an on/off switch per key and grant.
The shared machine uses a fixed placeholder api key, "keyferry", which is not a secret.
Relay tokens are only for TCP listeners and TCP forwards.

Usage:
  keyferry serve [--state-dir DIR] [--listen unix:PATH|tcp:ADDR] [--ui unix:PATH|tcp:ADDR|off] [--verbose]
  keyferry expose --unix PATH [--listen 127.0.0.1:0]
  keyferry key add NAME --provider openai|anthropic|generic [--base-url URL] [--auth-header H] [--auth-scheme S]
  keyferry key edit NAME [--provider P] [--base-url URL] [--auth-header H] [--auth-scheme S] [--rotate]
  keyferry key list
  keyferry key remove NAME
  keyferry key enable|disable NAME
  keyferry grant add NAME [--bind a,b] [--socket PATH] [--off]
  keyferry grant bind NAME --key KEY
  keyferry grant unbind NAME --key KEY
  keyferry grant edit NAME [--socket PATH] [--clear-socket]
  keyferry grant list
  keyferry grant remove NAME
  keyferry grant enable|disable NAME
  keyferry token issue --grant NAME [--ttl 4h] [--quota N] [--label TEXT] [--out FILE]
  keyferry token list
  keyferry token revoke ID
  keyferry version

"upstream" is an alias of "key". "entry" is an alias of "grant".
Provider keys are read from stdin, never from a flag.
One serve process routes every grant. Select a grant with /g/NAME/ on the shared socket,
or give that grant its own Unix socket. TCP requires a token.
`
