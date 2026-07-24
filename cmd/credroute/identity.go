// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4): `identity add` / `identity
// edit`, imperative commands so an operator or agent never hand-writes
// identities{} in config.yaml.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hasandenizuk/credroute/internal/config"
)

func cmdIdentity(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credroute identity: expected subcommand \"add\" or \"edit\"")
		return 1
	}
	switch args[0] {
	case "add":
		return cmdIdentityAdd(args[1:])
	case "edit":
		return cmdIdentityEdit(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "credroute identity: unknown subcommand %q (expected: add, edit)\n", args[0])
		return 1
	}
}

func cmdIdentityAdd(args []string) int {
	fs := flag.NewFlagSet("identity add", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	label := fs.String("label", "", "human-readable label for this identity")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute identity add: expected exactly one identity id (usually an email), e.g. \"identity add alex@example.com --label 'Alex personal'\"")
		return 1
	}
	id := fs.Arg(0)

	return withConfigEdit(g, "identity add", id, func(doc *config.Document) error {
		return doc.AddIdentity(id, *label)
	})
}

func cmdIdentityEdit(args []string) int {
	fs := flag.NewFlagSet("identity edit", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	label := fs.String("label", "", "replace this identity's label")
	var addCreds stringList
	fs.Var(&addCreds, "add-credential", "add or replace a credential: platform:access:type:vault-handle[#slot] (repeatable), e.g. google:read-only:oauth:age://google/alex/oauth-ro.json.age#~/.config/gws/profiles/personal-view")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute identity edit: expected exactly one identity id")
		return 1
	}
	id := fs.Arg(0)

	var setLabel *string
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "label" {
			v := *label
			setLabel = &v
		}
	})

	if setLabel == nil && len(addCreds) == 0 {
		fmt.Fprintln(os.Stderr, "credroute identity edit: nothing to do (pass --label and/or --add-credential)")
		return 1
	}

	creds, err := parseCredentialSpecs(addCreds)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute identity edit:", err)
		return 1
	}

	return withConfigEdit(g, "identity edit", id, func(doc *config.Document) error {
		if setLabel != nil {
			if err := doc.SetIdentityLabel(id, *setLabel); err != nil {
				return err
			}
		}
		for _, c := range creds {
			if err := doc.UpsertCredential(id, c.platform, c.access, c.cred); err != nil {
				return err
			}
		}
		return nil
	})
}

// credSpec is one parsed --add-credential argument.
type credSpec struct {
	platform string
	access   string
	cred     config.Credential
}

// parseCredentialSpecs parses every --add-credential value of the form
// "platform:access:type:vault-handle[#slot]". The vault handle itself
// contains a colon (its own "scheme://" prefix), so only the first three
// colons are treated as field separators; an optional slot is instead
// separated from the vault handle by "#", a character that appears in
// neither vault handles nor filesystem paths in practice.
func parseCredentialSpecs(specs []string) ([]credSpec, error) {
	var out []credSpec
	for _, s := range specs {
		parts := strings.SplitN(s, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("--add-credential %q: expected platform:access:type:vault-handle[#slot]", s)
		}
		platform, access, typ, rest := parts[0], parts[1], parts[2], parts[3]
		if platform == "" || access == "" || typ == "" || rest == "" {
			return nil, fmt.Errorf("--add-credential %q: platform, access, type, and vault-handle are all required", s)
		}
		vaultHandle, slot, _ := strings.Cut(rest, "#")
		if vaultHandle == "" {
			return nil, fmt.Errorf("--add-credential %q: vault handle is required", s)
		}
		out = append(out, credSpec{
			platform: platform,
			access:   access,
			cred:     config.Credential{Type: typ, Vault: vaultHandle, Slot: slot},
		})
	}
	return out, nil
}
