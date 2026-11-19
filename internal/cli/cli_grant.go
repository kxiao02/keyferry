package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"keyferry/internal/store"
)

func newFlag(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func cmdKeyEdit(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlag("key edit", stderr)
	provider := fs.String("provider", "", "openai, anthropic, or generic")
	base := fs.String("base-url", "", "origin URL")
	authHeader := fs.String("auth-header", "", "generic header")
	authScheme := fs.String("auth-scheme", "", "generic scheme")
	rotate := fs.Bool("rotate", false, "read a replacement key from stdin")
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: key edit NAME [--rotate]")
		return 2
	}
	newKey := ""
	if *rotate {
		newKey, err = readSecret(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
			return 1
		}
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.EditKey(positionals[0], *provider, *base, *authHeader, *authScheme, newKey); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "key\t%s\n", positionals[0])
	return 0
}

func cmdKeyEnabled(args []string, on bool, stdout, stderr io.Writer) int {
	fs := newFlag("key enable", stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: key enable|disable NAME")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.SetKeyEnabled(positionals[0], on); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	word := "disabled"
	if on {
		word = "enabled"
	}
	fmt.Fprintf(stdout, "%s\t%s\n", word, positionals[0])
	return 0
}

func cmdGrant(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "keyferry: grant requires add, edit, list, remove, enable, disable, bind, or unbind")
		return 2
	}
	switch args[0] {
	case "add":
		return cmdGrantAdd(args[1:], stdout, stderr)
	case "edit":
		return cmdGrantEdit(args[1:], stdout, stderr)
	case "list":
		return cmdGrantList(args[1:], stdout, stderr)
	case "remove", "rm", "delete":
		return cmdGrantRemove(args[1:], stdout, stderr)
	case "enable":
		return cmdGrantEnabled(args[1:], true, stdout, stderr)
	case "disable":
		return cmdGrantEnabled(args[1:], false, stdout, stderr)
	case "bind":
		return cmdGrantBind(args[1:], true, stdout, stderr)
	case "unbind":
		return cmdGrantBind(args[1:], false, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "keyferry: unknown grant command")
		return 2
	}
}

func cmdGrantAdd(args []string, stdout, stderr io.Writer) int {
	fs := newFlag("grant add", stderr)
	bind := fs.String("bind", "", "comma-separated key names")
	socket := fs.String("socket", "", "optional extra unix socket")
	off := fs.Bool("off", false, "create the grant disabled")
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: grant add NAME [--bind a,b] [--socket PATH]")
		return 2
	}
	on := !*off
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.PutGrant(store.Grant{
		Name:    positionals[0],
		Enabled: boolPtr(on),
		Keys:    splitNames(*bind),
		Socket:  *socket,
	}); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "grant\t%s\n", positionals[0])
	return 0
}

func cmdGrantEdit(args []string, stdout, stderr io.Writer) int {
	fs := newFlag("grant edit", stderr)
	socket := fs.String("socket", "", "extra unix socket")
	clear := fs.Bool("clear-socket", false, "remove the extra socket")
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: grant edit NAME [--socket PATH] [--clear-socket]")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	path := *socket
	if *clear {
		path = ""
	}
	if err := st.SetGrantSocket(positionals[0], path); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "grant\t%s\n", positionals[0])
	return 0
}

func cmdGrantList(args []string, stdout, stderr io.Writer) int {
	fs := newFlag("grant list", stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(stderr, "keyferry: grant list takes no names")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	list, err := st.ListGrants()
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintln(stdout, "name\tenabled\tkeys\tsocket")
	for _, item := range list {
		fmt.Fprintf(stdout, "%s\t%t\t%s\t%s\n", item.Name, item.Enabled, strings.Join(item.Keys, ","), item.Socket)
	}
	return 0
}

func cmdGrantRemove(args []string, stdout, stderr io.Writer) int {
	fs := newFlag("grant remove", stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: grant remove NAME")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.DeleteGrant(positionals[0]); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "removed\t%s\n", positionals[0])
	return 0
}

func cmdGrantEnabled(args []string, on bool, stdout, stderr io.Writer) int {
	fs := newFlag("grant enable", stderr)
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "keyferry: usage: grant enable|disable NAME")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if err := st.SetGrantEnabled(positionals[0], on); err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	word := "disabled"
	if on {
		word = "enabled"
	}
	fmt.Fprintf(stdout, "%s\t%s\n", word, positionals[0])
	return 0
}

func cmdGrantBind(args []string, bind bool, stdout, stderr io.Writer) int {
	fs := newFlag("grant bind", stderr)
	key := fs.String("key", "", "key name")
	state := fs.String("state-dir", "", "state directory")
	positionals, err := parseMixed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 || *key == "" {
		fmt.Fprintln(stderr, "keyferry: usage: grant bind|unbind NAME --key KEY")
		return 2
	}
	st, code := openState(*state, stderr)
	if st == nil {
		return code
	}
	if bind {
		err = st.Bind(positionals[0], *key)
	} else {
		err = st.Unbind(positionals[0], *key)
	}
	if err != nil {
		fmt.Fprintf(stderr, "keyferry: %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "grant\t%s\n", positionals[0])
	return 0
}

func splitNames(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func boolPtr(on bool) *bool { return &on }
