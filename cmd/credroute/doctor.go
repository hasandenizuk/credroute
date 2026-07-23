// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

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
