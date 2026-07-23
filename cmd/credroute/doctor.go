// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
)

type doctorCheck struct {
	Name   string
	OK     bool
	Detail string
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	var checks []doctorCheck
	allGreen := true
	add := func(name string, ok bool, detail string) {
		checks = append(checks, doctorCheck{Name: name, OK: ok, Detail: detail})
		if !ok {
			allGreen = false
		}
	}

	cfg, err := config.Load(g.configPath)
	if err != nil {
		add("config parses", false, err.Error())
	} else {
		add("config parses", true, cfg.Path)

		result := config.Validate(cfg)
		if result.OK() {
			add("config validates", true, fmt.Sprintf("%d warning(s)", len(result.Warnings)))
		} else {
			add("config validates", false, fmt.Sprintf("%d error(s)", len(result.Errors)))
		}

		if cfg.Vault.Backend != "age" {
			add("vault backend supported", false, fmt.Sprintf("backend %q is not implemented in this build", cfg.Vault.Backend))
		} else {
			add("vault backend supported", true, "age")

			storeDir, expErr := rules.ExpandHome(cfg.Vault.Age.StoreDir)
			if expErr != nil {
				add("vault store_dir exists", false, expErr.Error())
			} else if info, statErr := os.Stat(storeDir); statErr == nil && info.IsDir() {
				add("vault store_dir exists", true, storeDir)
			} else {
				add("vault store_dir exists", false, storeDir)
			}

			idFile, expErr := rules.ExpandHome(cfg.Vault.Age.IdentityFile)
			if expErr != nil {
				add("age identity_file readable", false, expErr.Error())
			} else if f, openErr := os.Open(idFile); openErr == nil {
				f.Close()
				add("age identity_file readable", true, idFile)
			} else {
				add("age identity_file readable", false, idFile+": "+openErr.Error())
			}
		}
	}

	if path, err := exec.LookPath("age"); err == nil {
		add("age binary on PATH", true, path)
	} else {
		add("age binary on PATH", false, "not found")
	}

	addSidecarCheck(add, cfg)

	for _, c := range checks {
		mark := "OK  "
		if !c.OK {
			mark = "FAIL"
		}
		if c.Detail != "" {
			fmt.Printf("[%s] %-28s %s\n", mark, c.Name, c.Detail)
		} else {
			fmt.Printf("[%s] %s\n", mark, c.Name)
		}
	}

	if allGreen {
		return 0
	}
	return 1
}

// addSidecarCheck validates every attestation sidecar's HMAC (spec 5.4)
// and flags any that are tampered, recorded as a mismatch, or older than
// defaults.sidecar_max_age (milestone 2). cfg may be nil if config.Load
// already failed; the check still runs (staleness just can't be judged
// without a configured max age).
func addSidecarCheck(add func(name string, ok bool, detail string), cfg *config.Config) {
	paths, err := attest.ListPaths()
	if err != nil {
		add("attestation sidecars", false, err.Error())
		return
	}
	if len(paths) == 0 {
		add("attestation sidecars", true, "none recorded yet")
		return
	}

	var maxAge time.Duration
	if cfg != nil && cfg.Defaults.SidecarMaxAge != "" {
		if parsed, parseErr := time.ParseDuration(cfg.Defaults.SidecarMaxAge); parseErr == nil {
			maxAge = parsed
		}
	}

	var flagged []string
	for _, p := range paths {
		name := filepath.Base(p)
		rec, readErr := attest.ReadPath(p)
		switch {
		case errors.Is(readErr, attest.ErrTampered):
			flagged = append(flagged, name+": tampered (HMAC check failed)")
		case readErr != nil:
			flagged = append(flagged, name+": "+readErr.Error())
		case rec.Status == attest.StatusMismatch:
			flagged = append(flagged, fmt.Sprintf("%s: mismatch (slot=%s)", name, rec.Slot))
		case rec.Status == attest.StatusUnreadable:
			flagged = append(flagged, fmt.Sprintf("%s: last check was unreadable (slot=%s)", name, rec.Slot))
		case maxAge > 0 && time.Since(rec.CheckedAt) > maxAge:
			flagged = append(flagged, fmt.Sprintf("%s: stale (slot=%s, checked %s)", name, rec.Slot, rec.CheckedAt.Format(time.RFC3339)))
		}
	}

	if len(flagged) == 0 {
		add("attestation sidecars", true, fmt.Sprintf("%d sidecar(s), all HMAC-valid and fresh", len(paths)))
		return
	}
	add("attestation sidecars", false, fmt.Sprintf("%d/%d flagged: %s", len(flagged), len(paths), strings.Join(flagged, "; ")))
}
