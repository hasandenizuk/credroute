// allow-claude-code: see common.go header; small shared flag helper for
// the new identity/route commands (milestone: agent-native command
// layer).
package main

import "strings"

// stringList implements flag.Value, collecting every occurrence of a
// repeatable flag (e.g. "--platform google --platform github") into a
// slice, in the order given.
type stringList []string

func (s *stringList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
