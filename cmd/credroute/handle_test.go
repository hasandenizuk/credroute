// allow-claude-code: see handle.go header.
package main

import "testing"

func TestHandleRevealAllowed(t *testing.T) {
	cases := []struct {
		name        string
		forceReveal bool
		isTTY       bool
		want        bool
	}{
		{"neither flag nor tty", false, false, false},
		{"tty but no flag", false, true, false},
		{"flag but no tty (piped/redirected)", true, false, false},
		{"flag and tty", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := handleRevealAllowed(c.forceReveal, c.isTTY)
			if got != c.want {
				t.Fatalf("handleRevealAllowed(%v, %v) = %v, want %v", c.forceReveal, c.isTTY, got, c.want)
			}
			if !got && reason == "" {
				t.Fatal("a refusal must always explain why")
			}
			if got && reason != "" {
				t.Fatalf("an allowed reveal should carry no refusal reason, got %q", reason)
			}
		})
	}
}
