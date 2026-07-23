// allow-claude-code: see glob.go header.
package rules

import (
	"fmt"

	"github.com/hasandenizuk/credroute/internal/config"
)

// Query is the context a resolve/explain request is evaluated against.
type Query struct {
	Dir      string
	Platform string
	Task     string
}

// ConditionTrace is one condition (key) checked for one rule during
// evaluation, for `credroute explain`.
type ConditionTrace struct {
	Key      string
	Expected string
	Actual   string
	Pass     bool
}

// RuleTrace is the evaluation record for one rule.
type RuleTrace struct {
	RuleID     string
	Index      int
	Matched    bool
	Evaluated  bool // false when evaluation stopped before reaching this rule
	Conditions []ConditionTrace
}

// Resolution is the successful outcome: which rule won, and the identity
// and access level it resolved to.
type Resolution struct {
	Rule            config.Rule
	Index           int
	Identity        string
	IdentityLabel   string
	Access          string
	Credential      config.Credential
	CredentialFound bool
}

// Result is the full outcome of evaluating a query against a config,
// carrying the trace needed for `explain` plus the winning resolution (if
// any) needed for `resolve`.
type Result struct {
	Query      Query
	Trace      []RuleTrace
	Resolution *Resolution // nil if no rule matched
}

// Evaluate runs the rule engine: ordered, first-match-wins for the
// resolution. Every rule's conditions are always checked (not just up to
// the winner) so the full trace has real per-condition data for
// `explain --all`; only Result.Resolution reflects first-match-wins.
// Trace[i].Evaluated marks the rules `explain` (without --all) should
// still display: everything up to and including the winner, or every
// rule when nothing matched.
func Evaluate(cfg *config.Config, q Query) (*Result, error) {
	res := &Result{Query: q}

	winner := -1
	for i, rule := range cfg.Rules {
		matched, conds, err := evalRule(cfg, rule, q)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		res.Trace = append(res.Trace, RuleTrace{
			RuleID:     rule.ID,
			Index:      i,
			Matched:    matched,
			Conditions: conds,
		})
		if matched && winner == -1 {
			winner = i
		}
	}

	for i := range res.Trace {
		if winner == -1 || i <= winner {
			res.Trace[i].Evaluated = true
		}
	}

	if winner == -1 {
		return res, nil
	}

	rule := cfg.Rules[winner]
	resolution := &Resolution{
		Rule:     rule,
		Index:    winner,
		Identity: rule.Use.Identity,
		Access:   rule.Use.Access,
	}
	if identity, ok := cfg.Identities[rule.Use.Identity]; ok {
		resolution.IdentityLabel = identity.Label
		if len(q.Platform) > 0 {
			if plat, ok := identity.Platforms[q.Platform]; ok {
				if cred, ok := plat.Credentials[rule.Use.Access]; ok {
					resolution.Credential = cred
					resolution.CredentialFound = true
				}
			}
		}
	}
	res.Resolution = resolution
	return res, nil
}

// evalRule checks one rule's match block against q and returns whether it
// matched plus a per-condition trace for explain.
func evalRule(cfg *config.Config, rule config.Rule, q Query) (bool, []ConditionTrace, error) {
	var conds []ConditionTrace
	pass := true

	if rule.Match.Client != "" {
		ok, actual, err := matchClient(cfg, rule.Match.Client, q.Dir)
		if err != nil {
			return false, nil, err
		}
		conds = append(conds, ConditionTrace{Key: "client", Expected: rule.Match.Client, Actual: actual, Pass: ok})
		if !ok {
			pass = false
		}
	}

	if rule.Match.Dir != "" {
		ok, err := matchDir(rule.Match.Dir, q.Dir)
		if err != nil {
			return false, nil, err
		}
		conds = append(conds, ConditionTrace{Key: "dir", Expected: rule.Match.Dir, Actual: q.Dir, Pass: ok})
		if !ok {
			pass = false
		}
	}

	if len(rule.Match.Platform) > 0 {
		ok := containsString(rule.Match.Platform, q.Platform)
		conds = append(conds, ConditionTrace{Key: "platform", Expected: joinOr(rule.Match.Platform), Actual: q.Platform, Pass: ok})
		if !ok {
			pass = false
		}
	}

	if len(rule.Match.Task) > 0 {
		ok := q.Task != "" && containsString(rule.Match.Task, q.Task)
		actual := q.Task
		if actual == "" {
			actual = "(none)"
		}
		conds = append(conds, ConditionTrace{Key: "task", Expected: joinOr(rule.Match.Task), Actual: actual, Pass: ok})
		if !ok {
			pass = false
		}
	}

	return pass, conds, nil
}

// matchClient reports whether dir falls under any root glob of the named
// client, expanding "~" in both the client roots and dir.
func matchClient(cfg *config.Config, clientName, dir string) (bool, string, error) {
	client, ok := cfg.Clients[clientName]
	if !ok {
		return false, "(client not defined)", nil
	}
	expandedDir, err := ExpandHome(dir)
	if err != nil {
		return false, "", err
	}
	for _, root := range client.Roots {
		expandedRoot, err := ExpandHome(root)
		if err != nil {
			return false, "", err
		}
		if MatchGlob(expandedRoot, expandedDir) {
			return true, dir, nil
		}
	}
	return false, dir, nil
}

// matchDir reports whether dir matches the glob pattern, expanding "~" in
// both.
func matchDir(pattern, dir string) (bool, error) {
	expandedPattern, err := ExpandHome(pattern)
	if err != nil {
		return false, err
	}
	expandedDir, err := ExpandHome(dir)
	if err != nil {
		return false, err
	}
	return MatchGlob(expandedPattern, expandedDir), nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func joinOr(list []string) string {
	out := ""
	for i, v := range list {
		if i > 0 {
			out += "|"
		}
		out += v
	}
	return out
}
