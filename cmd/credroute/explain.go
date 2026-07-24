// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/hasandenizuk/credroute/internal/rules"
)

type explainTrace struct {
	RuleID     string             `json:"rule_id"`
	Index      int                `json:"index"`
	Matched    bool               `json:"matched"`
	Evaluated  bool               `json:"evaluated"`
	Conditions []explainCondition `json:"conditions,omitempty"`
}

type explainCondition struct {
	Key      string `json:"key"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Pass     bool   `json:"pass"`
}

type explainResponse struct {
	Request requestInfo    `json:"request"`
	Trace   []explainTrace `json:"trace"`
	Result  *explainResult `json:"result,omitempty"`
}

type explainResult struct {
	Identity    string           `json:"identity"`
	AccessLevel string           `json:"access_level"`
	VaultHandle string           `json:"vault_handle,omitempty"`
	Slot        string           `json:"slot,omitempty"`
	MatchedRule *matchedRuleInfo `json:"matched_rule"`
}

func cmdExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	all := fs.Bool("all", false, "show every rule, including ones after the winning match")
	platform := fs.String("platform", "", "platform to resolve (required)")
	task := fs.String("task", "", "task tag")
	dir := fs.String("dir", "", "directory to resolve for (default: cwd)")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute explain: --platform is required")
		return 1
	}

	queryDir, err := resolveQueryDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute explain:", err)
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute explain:", err)
		return 5
	}

	result, err := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: *platform, Task: *task})
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute explain:", err)
		return 5
	}

	resp := explainResponse{Request: requestInfo{Platform: *platform, Dir: queryDir, Task: *task}}
	for _, t := range result.Trace {
		if !*all && !t.Evaluated {
			// Default (non --all) mode: stop annotating once evaluation
			// stopped at the winning rule. Still list the rule id so the
			// reader sees it was skipped, matching the spec's example
			// output ("(not evaluated - stopped at first match)").
			resp.Trace = append(resp.Trace, explainTrace{RuleID: t.RuleID, Index: t.Index, Evaluated: false})
			continue
		}
		et := explainTrace{RuleID: t.RuleID, Index: t.Index, Matched: t.Matched, Evaluated: t.Evaluated}
		for _, c := range t.Conditions {
			et.Conditions = append(et.Conditions, explainCondition{Key: c.Key, Expected: c.Expected, Actual: c.Actual, Pass: c.Pass})
		}
		resp.Trace = append(resp.Trace, et)
	}

	if result.Resolution != nil {
		res := result.Resolution
		resp.Result = &explainResult{
			Identity:    res.Identity,
			AccessLevel: res.Access,
			MatchedRule: &matchedRuleInfo{ID: res.Rule.ID, Index: res.Index},
		}
		if res.CredentialFound {
			resp.Result.VaultHandle = res.Credential.Vault
			resp.Result.Slot = expandSlot(res.Credential.Slot)
		}
	}

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
	} else {
		printExplainHuman(resp)
	}

	if result.Resolution == nil {
		return 2
	}
	return 0
}

func printExplainHuman(resp explainResponse) {
	fmt.Printf("context   dir=%s  platform=%s", resp.Request.Dir, resp.Request.Platform)
	if resp.Request.Task != "" {
		fmt.Printf("  task=%s", resp.Request.Task)
	}
	fmt.Println()
	fmt.Println()

	for i, t := range resp.Trace {
		if !t.Evaluated && len(t.Conditions) == 0 && !t.Matched {
			fmt.Printf("  %d. %-18s (not evaluated - stopped at first match)\n", i+1, t.RuleID)
			continue
		}
		verdict := "MISS"
		if t.Matched {
			verdict = "MATCH"
		}
		fmt.Printf("  %d. %-18s %s", i+1, t.RuleID, verdict)
		if len(t.Conditions) == 0 {
			fmt.Print("   (catch-all: no conditions)")
		}
		for _, c := range t.Conditions {
			mark := "ok"
			if !c.Pass {
				mark = fmt.Sprintf("miss (want %s, got %s)", c.Expected, c.Actual)
			}
			fmt.Printf("   %s=%s", c.Key, mark)
		}
		fmt.Println()
	}

	fmt.Println()
	if resp.Result == nil {
		fmt.Println("result    no rule matched - refusing (exit 2)")
		return
	}
	fmt.Printf("result    identity=%s  access=%s\n", resp.Result.Identity, resp.Result.AccessLevel)
	if resp.Result.VaultHandle != "" {
		fmt.Printf("          vault=%s\n", resp.Result.VaultHandle)
	}
	if resp.Result.Slot != "" {
		fmt.Printf("          slot=%s\n", resp.Result.Slot)
	}
	fmt.Printf("          matched_rule=%s (index %d)\n", resp.Result.MatchedRule.ID, resp.Result.MatchedRule.Index)
}
